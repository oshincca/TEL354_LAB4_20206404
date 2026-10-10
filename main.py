import asyncio
import itertools
import json
import re
import sys

import requests
import yaml

# IP del controlador Floodlight (se puede pasar como argumento: python3 main.py <ip>)
CONTROLLER_IP = sys.argv[1] if len(sys.argv) > 1 else '10.100.18.253'
BASE_URL = f'http://{CONTROLLER_IP}:8080'
FLOW_URL = BASE_URL + '/wm/staticflowpusher/json'
FLOW_PRIORITY = '1000'
PROTO_NUM = {'TCP': '0x06', 'UDP': '0x11'}
MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
HANDLERS = itertools.count(1)


# ----------------------------------------------------------------------------
# Modelo de datos
# ----------------------------------------------------------------------------
class Student:
    def __init__(self, name, mac, code=None):
        self.name = name
        self.mac = mac
        self.code = code

    def __str__(self):
        return f"{self.name} ({self.mac})"


class Service:
    def __init__(self, name, protocol, port):
        self.name = name
        self.protocol = protocol.upper()
        self.port = int(port)

    def __str__(self):
        return f"{self.name} [{self.protocol}/{self.port}]"


class Server:
    def __init__(self, name, ip, services):
        self.name = name
        self.ip = ip
        self.services = [Service(s["name"], s["protocol"], s["port"]) for s in services]

    def get_service(self, name):
        return next((s for s in self.services if s.name == name), None)

    def __str__(self):
        return f"{self.name} ({self.ip})"


class Course:
    def __init__(self, code, name, state, students, servers):
        self.code = code
        self.name = name
        self.state = state
        self.students = list(students)   # nombres de alumnos
        self.servers = list(servers)     # [{"name": ..., "allowed_services": [...]}]

    def is_active(self):
        return self.state == "ACTIVE"

    def allows(self, student_name, server_name, service_name):
        """El curso otorga acceso si está ACTIVE, el alumno está matriculado
        y el servidor/servicio figuran en su lista."""
        if not self.is_active() or student_name not in self.students:
            return False
        return any(s["name"] == server_name and service_name in s["allowed_services"]
                   for s in self.servers)

    def grants_service(self, server_name, service_name):
        return any(s["name"] == server_name and service_name in s["allowed_services"]
                   for s in self.servers)

    def __str__(self):
        return f"{self.code} - {self.name} [{self.state}]"


class Connection:
    def __init__(self, student, server, services, route):
        self.handler = f"conn-{next(HANDLERS)}"
        self.student = student
        self.server = server
        self.services = services
        self.route = route
        self.flow_names = []


# ----------------------------------------------------------------------------
# Carga / exportación de datos
# ----------------------------------------------------------------------------
def load_data(filename):
    with open(filename, "r") as file:
        data = yaml.safe_load(file)
    students = [Student(x["name"], x["mac"]) for x in data["students"]]
    servers = [Server(y["name"], y["ip"], y["services"]) for y in data["servers"]]
    courses = [Course(z["code"], z["name"], z["state"], z["students"], z["servers"])
               for z in data["courses"]]
    return students, servers, courses


def export_data(filename, db):
    data = {
        "students": [{"name": s.name, "mac": s.mac} for s in db["students"]],
        "courses": [{"name": c.name, "code": c.code, "state": c.state,
                     "students": c.students, "servers": c.servers} for c in db["courses"]],
        "servers": [{"name": s.name, "ip": s.ip,
                     "services": [{"name": x.name, "protocol": x.protocol, "port": x.port}
                                  for x in s.services]} for s in db["servers"]],
    }
    with open(filename, "w") as file:
        yaml.safe_dump(data, file, sort_keys=False, allow_unicode=True)


def is_authorized(student, server, service, courses):
    return any(c.allows(student.name, server.name, service.name) for c in courses)


# ----------------------------------------------------------------------------
# Northbound API de Floodlight
# ----------------------------------------------------------------------------
def get_attachment_point(controller_ip, mac):
    endpoint = '/wm/device/'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(
        url,
        params={'mac': mac}
    )
    result, = response.json()
    attachment_points = result.get("attachmentPoint", [])

    if not attachment_points:
        return None, None

    attachment_point, = attachment_points
    return attachment_point["switchDPID"], attachment_point["port"]


def get_route(controller_ip, src_mac, dst_mac):
    src_sw_dpid, src_sw_port = get_attachment_point(controller_ip, src_mac)
    dst_sw_dpid, dst_sw_port = get_attachment_point(controller_ip, dst_mac)
    endpoint = f'/wm/topology/route/{src_sw_dpid}/{src_sw_port}/{dst_sw_dpid}/{dst_sw_port}/json'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url)
    return response.json()


def get_device(params):
    """Consulta /wm/device/ y devuelve el primer dispositivo (o None)."""
    response = requests.get(BASE_URL + '/wm/device/', params=params, timeout=5)
    devices = response.json()
    return devices[0] if devices else None


def get_ip_by_mac(mac):
    device = get_device({'mac': mac})
    ips = device.get("ipv4", []) if device else []
    return ips[0] if ips else None


def get_mac_by_ip(ip):
    device = get_device({'ipv4': ip})
    macs = device.get("mac", []) if device else []
    return macs[0] if macs else None


# ----------------------------------------------------------------------------
# Construcción de rutas (inserción asíncrona de flow entries)
# ----------------------------------------------------------------------------
def _port_number(port):
    return port.get("portNumber") if isinstance(port, dict) else port


def hop_triplets(route):
    """La ruta de Floodlight es una lista [(sw, puerto_entrada), (sw, puerto_salida), ...].
    Devuelve [(dpid, in_port, out_port)] por cada switch del camino."""
    hops = [(n.get("switch") or n.get("switchDPID"), _port_number(n["port"])) for n in route]
    return [(hops[i][0], hops[i][1], hops[i + 1][1]) for i in range(0, len(hops) - 1, 2)]


def make_flow(name, dpid, in_port, out_port, **match):
    flow = {
        "switch": dpid,
        "name": name,
        "priority": FLOW_PRIORITY,
        "active": "true",
        "in_port": str(in_port),
        "actions": f"output={out_port}",
    }
    flow.update(match)
    return flow


def build_flows(route, conn, student_ip, server_mac):
    """Genera las flow entries (ARP + IPv4/L4) en ambos sentidos para cada switch."""
    st, sv = conn.student, conn.server
    flows = []
    for idx, (dpid, p_in, p_out) in enumerate(hop_triplets(route)):
        base = f"{conn.handler}_{dpid.replace(':', '')}_{idx}"
        # ARP (L2): alumno -> servidor y servidor -> alumno
        flows.append(make_flow(f"{base}_arp_f", dpid, p_in, p_out,
                               eth_type="0x0806", eth_src=st.mac))
        flows.append(make_flow(f"{base}_arp_r", dpid, p_out, p_in,
                               eth_type="0x0806", eth_src=server_mac))
        for svc in conn.services:
            proto = svc.protocol.lower()
            common = {"eth_type": "0x0800", "ip_proto": PROTO_NUM[svc.protocol]}
            # host -> servidor: L2 + L3 + L4 (puerto destino = puerto del servicio)
            flows.append(make_flow(f"{base}_{svc.name}_f", dpid, p_in, p_out,
                                   eth_src=st.mac, eth_dst=server_mac,
                                   ipv4_src=student_ip, ipv4_dst=sv.ip,
                                   **common, **{f"{proto}_dst": str(svc.port)}))
            # servidor -> host (puerto origen = puerto del servicio)
            flows.append(make_flow(f"{base}_{svc.name}_r", dpid, p_out, p_in,
                                   eth_src=server_mac, eth_dst=st.mac,
                                   ipv4_src=sv.ip, ipv4_dst=student_ip,
                                   **common, **{f"{proto}_src": str(svc.port)}))
    return flows


async def _push_flow(flow):
    resp = await asyncio.to_thread(requests.post, FLOW_URL, data=json.dumps(flow), timeout=5)
    return flow["name"], resp.ok


async def _delete_flow(name):
    resp = await asyncio.to_thread(requests.delete, FLOW_URL, data=json.dumps({"name": name}), timeout=5)
    return name, resp.ok


async def _run_all(coros):
    return await asyncio.gather(*coros)


def build_route(route, conn, student_ip, server_mac):
    """Inserta (de forma asíncrona) las flow entries necesarias para la conexión.
    Devuelve la lista de flows que no pudieron instalarse."""
    flows = build_flows(route, conn, student_ip, server_mac)
    results = asyncio.run(_run_all([_push_flow(f) for f in flows]))
    conn.flow_names = [name for name, ok in results if ok]
    return [name for name, ok in results if not ok]


def remove_route(conn):
    results = asyncio.run(_run_all([_delete_flow(n) for n in conn.flow_names]))
    return [name for name, ok in results if not ok]


# ----------------------------------------------------------------------------
# Utilidades de CLI
# ----------------------------------------------------------------------------
def pick(items, label, title):
    if not items:
        print("(no hay elementos)")
        return None
    print(title)
    for i, item in enumerate(items, 1):
        print(f"  {i}. {label(item)}")
    sel = input("Opción: ").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(items):
        return items[int(sel) - 1]
    print("Opción inválida.")
    return None


def submenu(title, options):
    print(f"\n=== {title} ===")
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    print("  0. Volver")
    return input("Opción: ").strip()


def menu():
    print("\n===== Gestor SDN de acceso a servidores =====")
    for i, opt in enumerate(["Importar", "Exportar", "Cursos", "Alumnos", "Servidores",
                             "Políticas", "Conexiones", "Salir"], 1):
        print(f"  {i}. {opt}")
    return input("Opción: ").strip()


# ----------------------------------------------------------------------------
# Cursos
# ----------------------------------------------------------------------------
def show_course(course):
    print(f"Código: {course.code}\nNombre: {course.name}\nEstado: {course.state}")
    print("Alumnos: " + (", ".join(course.students) or "(ninguno)"))
    print("Servidores:")
    for s in course.servers:
        print(f"  - {s['name']}: {', '.join(s['allowed_services'])}")


def courses_menu(db):
    while True:
        op = submenu("Cursos", ["Listar", "Mostrar detalles", "Gestionar alumnos"])
        if op == "0":
            return
        if op == "1":
            for c in db["courses"]:
                print(f"  {c}")
        elif op == "2":
            course = pick(db["courses"], str, "Seleccione curso:")
            if course:
                show_course(course)
        elif op == "3":
            course = pick(db["courses"], str, "Seleccione curso:")
            if not course:
                continue
            action = input("1. Agregar alumno  2. Eliminar alumno: ").strip()
            if action == "1":
                candidates = [s for s in db["students"] if s.name not in course.students]
                st = pick(candidates, str, "Alumno a agregar:")
                if st:
                    course.students.append(st.name)
                    print(f"{st.name} agregado a {course.code}.")
            elif action == "2":
                name = pick(course.students, str, "Alumno a eliminar:")
                if name:
                    course.students.remove(name)
                    print(f"{name} eliminado de {course.code}.")


# ----------------------------------------------------------------------------
# Alumnos
# ----------------------------------------------------------------------------
def students_menu(db):
    while True:
        op = submenu("Alumnos", ["Crear", "Listar", "Mostrar detalles"])
        if op == "0":
            return
        if op == "1":
            name = input("Nombre: ").strip()
            mac = input("MAC (aa:bb:cc:dd:ee:ff): ").strip().lower()
            if not name or not MAC_RE.match(mac):
                print("Error: nombre vacío o MAC inválida.")
            elif any(s.mac.lower() == mac or s.name == name for s in db["students"]):
                print("Error: el alumno o la MAC ya existen.")
            else:
                db["students"].append(Student(name, mac))
                print(f"Alumno {name} creado.")
        elif op == "2":
            code = input("Filtrar por código de curso (Enter = todos): ").strip()
            names = None
            if code:
                course = next((c for c in db["courses"] if c.code == code), None)
                if not course:
                    print("Curso no encontrado.")
                    continue
                names = course.students
            for s in db["students"]:
                if names is None or s.name in names:
                    print(f"  {s}")
        elif op == "3":
            st = pick(db["students"], str, "Seleccione alumno:")
            if st:
                enrolled = [c.code for c in db["courses"] if st.name in c.students]
                print(f"Código: {st.code or '-'}\nNombre: {st.name}\nMAC: {st.mac}")
                print("Cursos: " + (", ".join(enrolled) or "(ninguno)"))


# ----------------------------------------------------------------------------
# Servidores
# ----------------------------------------------------------------------------
def servers_menu(db):
    while True:
        op = submenu("Servidores y servicios",
                     ["Listar", "Mostrar servicios", "Cursos con acceso a un servicio"])
        if op == "0":
            return
        if op == "1":
            for s in db["servers"]:
                print(f"  {s}")
        elif op in ("2", "3"):
            server = pick(db["servers"], str, "Seleccione servidor:")
            if not server:
                continue
            if op == "2":
                print(f"Servicios de {server.name}:")
                for svc in server.services:
                    print(f"  - {svc}")
            else:
                svc = pick(server.services, str, "Seleccione servicio:")
                if svc:
                    found = [c for c in db["courses"] if c.grants_service(server.name, svc.name)]
                    print(f"Cursos con acceso a {svc.name} en {server.name}:")
                    for c in found:
                        print(f"  {c}")
                    if not found:
                        print("  (ninguno)")


# ----------------------------------------------------------------------------
# Conexiones
# ----------------------------------------------------------------------------
def create_connection(db):
    student = pick(db["students"], str, "Seleccione alumno:")
    if not student:
        return
    server = pick(db["servers"], str, "Seleccione servidor:")
    if not server:
        return
    print("Servicios:")
    for i, svc in enumerate(server.services, 1):
        print(f"  {i}. {svc}")
    sel = input("Servicio (número, Enter = todos los autorizados): ").strip()

    if sel:
        if not (sel.isdigit() and 1 <= int(sel) <= len(server.services)):
            print("Opción inválida.")
            return
        svc = server.services[int(sel) - 1]
        if not is_authorized(student, server, svc, db["courses"]):
            print(f"Error: {student.name} NO está autorizado a usar {svc.name} en {server.name}.")
            return
        services = [svc]
    else:
        services = [s for s in server.services if is_authorized(student, server, s, db["courses"])]
        if not services:
            print(f"Error: {student.name} no está autorizado a ningún servicio de {server.name}.")
            return

    try:
        student_ip = get_ip_by_mac(student.mac)
        if not student_ip:
            student_ip = input("El controlador no conoce la IP del alumno; ingrésela: ").strip()
        server_mac = get_mac_by_ip(server.ip)
        if not server_mac:
            print(f"Error: el controlador no conoce el host con IP {server.ip}.")
            return
        route = get_route(CONTROLLER_IP, student.mac, server_mac)
    except (requests.RequestException, ValueError) as exc:
        print(f"Error consultando al controlador: {exc}")
        return
    if not route:
        print("Error: no se encontró una ruta entre el alumno y el servidor.")
        return

    conn = Connection(student, server, services, route)
    try:
        failed = build_route(route, conn, student_ip, server_mac)
    except requests.RequestException as exc:
        print(f"Error insertando flows: {exc}")
        return
    db["connections"].append(conn)
    print(f"Conexión {conn.handler} creada ({len(conn.flow_names)} flows instalados).")
    if failed:
        print(f"Aviso: fallaron {len(failed)} flows: {', '.join(failed)}")


def connections_menu(db):
    while True:
        op = submenu("Conexiones", ["Crear", "Listar", "Borrar"])
        if op == "0":
            return
        if op == "1":
            create_connection(db)
        elif op == "2":
            if not db["connections"]:
                print("(no hay conexiones)")
            for c in db["connections"]:
                svcs = ", ".join(s.name for s in c.services)
                print(f"  {c.handler}: {c.student.name} -> {c.server.name} [{svcs}] "
                      f"({len(c.flow_names)} flows)")
        elif op == "3":
            conn = pick(db["connections"],
                        lambda c: f"{c.handler}: {c.student.name} -> {c.server.name}",
                        "Seleccione conexión:")
            if not conn:
                continue
            if not all(is_authorized(conn.student, conn.server, s, db["courses"])
                       for s in conn.services):
                print(f"Error: {conn.student.name} no está autorizado; no se puede borrar la conexión.")
                continue
            try:
                failed = remove_route(conn)
            except requests.RequestException as exc:
                print(f"Error eliminando flows: {exc}")
                continue
            if failed:
                print(f"Aviso: no se pudieron borrar {len(failed)} flows: {', '.join(failed)}")
            db["connections"].remove(conn)
            print(f"Conexión {conn.handler} eliminada.")


def main():
    # Load data
    db = {"connections": []}
    db["students"], db["servers"], db["courses"] = load_data("database.yaml")

    while True:
        op = menu()
        if op == "1":
            fname = input("Archivo a importar: ").strip()
            try:
                db["students"], db["servers"], db["courses"] = load_data(fname)
                print("Datos importados.")
            except (OSError, KeyError, yaml.YAMLError) as exc:
                print(f"Error al importar: {exc}")
        elif op == "2":
            fname = input("Archivo de destino: ").strip()
            try:
                export_data(fname, db)
                print("Datos exportados.")
            except OSError as exc:
                print(f"Error al exportar: {exc}")
        elif op == "3":
            courses_menu(db)
        elif op == "4":
            students_menu(db)
        elif op == "5":
            servers_menu(db)
        elif op == "6":
            print("Políticas: no se implementa en este laboratorio.")
        elif op == "7":
            connections_menu(db)
        elif op == "8":
            print("Hasta luego.")
            break
        else:
            print("Opción inválida.")


if __name__ == "__main__":
    main()

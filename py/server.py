import io

from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import argparse, time, socket, json
from models.message import Message
from models.file import File

gMessageList = []
gFileData = []
login_usernames = {}
usernames = {}
prog_ver = "3.3.0"

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
uploads_dir = "./uploads"


@app.route('/access', methods=['POST'])
def access():
    global usernames
    data = request.get_json()
    if "username" in data:
        received_user = data["username"]
    else:
        raise AttributeError("Return a json file with the username key when using post on /access!")
    timestamp = time.time()
    if received_user in usernames and timestamp - usernames[received_user] < 10.0:
        return jsonify({"response": "This username is being used by another participant", "server_ip": None}), 400, {
            "Content-Type": "application/json"}
    else:
        login_usernames[received_user] = timestamp
        usernames[received_user] = timestamp
        return jsonify({"response": "You had successfully joined the chat",
                        "server_ip": socket.gethostbyname(socket.gethostname())}), 201, {
                   'Content-Type': 'application/json'}


@app.route("/heartbit", methods=["POST"])
def heartbit():
    global usernames
    data = request.get_json()
    if "username" in data:
        received_hb = data["username"]
    else:
        raise AttributeError("Return a json file with the username key when using post on /heartbit")
    print(received_hb + "^" + str(usernames))
    if received_hb in usernames:
        usernames[received_hb] = time.time()
        return jsonify({"response": "This user is online"}), 201, {'Content-Type': 'application/json'}
    else:
        return jsonify({"response": "Log in to access this session."}), 401, {'Content-Type': 'application/json'}


@app.route("/users")
def users():
    global usernames
    updated_users = {}
    for i in usernames:
        updated_users[i] = usernames[i]
    usernames = updated_users
    return jsonify(login_usernames), 200, {'Content-Type': 'application/json'}


@app.route('/msg', methods=['GET', 'POST'])
def msg():
    global gMessageList, usernames
    if request.method == "POST":
        data = request.get_json()
        if "sender" in data and "content" in data:
            received_message = Message(data["sender"], data["content"], data["type"])
        else:
            raise AttributeError("Send a json file with sender and content keys when using post on /msg!")
        gMessageList.append(received_message)
        if data["content"] == "> ❌ Goodbye! I left the chat <" and data["type"] == "info":
            usernames.pop(data["sender"])
        # return json.dumps(received_message.serialize, ensure_ascii=False).encode('utf8')
        return jsonify(received_message.serialize), 201, {'Content-Type': 'application/json'}
    elif request.method == "GET":
        # return json.dumps([str(i.serialize) for i in gMessageList], ensure_ascii=False).encode("utf8")
        return jsonify([i.serialize for i in gMessageList]), 200, {'Content-Type': 'application/json'}


@app.route("/msg-from-id", methods=["POST"])
def msg_from_id():
    global gMessageList
    data = request.get_json()
    if "sender" in data and "id" in data:
        msg = None
        for i in gMessageList:
            if i.id == data["id"]:
                msg = i
                break
        if msg:
            return jsonify(msg, 201, {"Content-Type": "application/json"})
        else:
            return jsonify({"response": "Message not found."}), 404, {'Content-Type': 'application/json'}


@app.route("/upload-file", methods=["POST"])
def upload_file():
    file = request.files["file"]
    data = dict(json.loads(request.files["json"].read().decode("latin-1")))
    print(str(type(data)))
    filename = secure_filename(file.filename)
    filepath = f"{uploads_dir}/{filename}"
    file.save(filepath)
    #gFilenames.append(filename)
    gFileData.append(File(data["sender"], data["filename"]))
    return jsonify({"response": "File uploaded to the server."}), 201, {"Content-Type": "application/json"}


"""@app.route("/filenames")
def filenames():
    global gFilenames
    return jsonify({"filenames": gFilenames}), 200, {"Content-Type": "application/json"}"""


@app.route("/download-file", methods=["POST"])
def download_file():
    data = request.get_json()
    for i in gFileData:
        if i.filename == data["filename"]:
            return send_file(f'{uploads_dir}/{i.filename}', as_attachment=True)
    else:
        return jsonify({"response": "The file specified doesn't exist."}), 404, {"Content-Type": "application/json"}


@app.route("/file-data")
def file_data():
    global gFileData
    return jsonify([i.serialize for i in gFileData]), 200, {"Content-Type": "application/json"}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AllHands Server", usage="python3 server.py")
    parser.add_argument("-v", "--version", action="version",
                        version="AllHands Server " + prog_ver + " by the What-do-I-know Company")
    parser.add_argument("-i", "--ip", type=str, default="0.0.0.0",
                        help="IP: Address the server listens to (by default the application listens to all the IPs)")
    parser.add_argument("-p", "--port", type=int, default=5000,
                        help="Port: Port the server listens at (default is 5000)")
    args = parser.parse_args()
    app.run(debug=True, host=args.ip, port=args.port)

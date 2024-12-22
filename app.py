from flask import Flask, request, render_template, redirect, session, jsonify, flash, url_for
from pymongo import MongoClient
import hashlib
import os
from dotenv import load_dotenv


app = Flask(__name__)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


load_dotenv()
uri = os.getenv("MONGODB_URI")
database_name = "CS499Final"
collection_name = "Users"


client = MongoClient(uri)
db = client["CS499Final"]
collection = db["Users"]

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role").lower()
    hashed_password = hash_password(password)
    #user = check_credentials(collection, username, password, role)
    user = collection.find_one({"Username": username, "Password": hashed_password, "Role": role})
    if user is not None:
        if role == "admin":
            print(f"Welcome, {username} as {role}!")
            return redirect(url_for('admin'))
        else:
            user_data = collection.find_one({"Username": username})
            brokerage = user_data.get("Brokerage", 0)
            retirement = user_data.get("Retirement", 0)
            print(retirement)
            print(brokerage)
            return render_template('user.html', brokerage=brokerage, retirement=retirement)
    else:
        flash("Username/Password incorrect or does not exist.")

    return render_template("index.html", boolean=True)

@app.route("/create_user", methods=["GET", "POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    brokerage = data.get("brokerage")
    retirement = data.get("retirement")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = hash_password(password)
    if collection.find_one({"Username": username}):
        return jsonify({"error": "Username already exists"}), 400
    
    collection.insert_one({"Username": username, "Password": hashed_password, "Role": role, "Brokerage": brokerage, "Retirement": retirement})
    return jsonify({"message": "User created successfully"}), 201

@app.route("/read_user/<username>", methods=["GET"])
def read_user(username):
    user = collection.find_one({"Username": username}, {"_id": 0})
    if user:
        return jsonify(user), 200
    return jsonify({"error": "User not found"}), 404

@app.route("/update_user", methods=["PUT"])
def update_user():
    data = request.json
    username = data.get("username")
    new_password = data.get("new_password")
    if not username or not new_password:
        return jsonify({"error": "Username and new password are required"}), 400
    
    hashed_password = hash_password(new_password)

    result = collection.update_one({"Username": username}, {"$set": {"Password": hashed_password}})
    if result.modified_count > 0:
        return jsonify({"message": "User updated successfully"}), 200
    return jsonify({"error": "User not found or no changes made"}), 404

@app.route("/delete_user/<username>", methods=["DELETE"])
def delete_user(username):
    result = collection.delete_one({"Username": username})
    if result.deleted_count > 0:
        return jsonify({"message": "User deleted successfully"}), 200
    return jsonify({"error": "User not found"}), 404

@app.route("/admin", methods=["GET", "POST"])
def admin():
    return render_template("admin.html")

@app.route("/user", methods=["GET", "POST"])
def user():
    return render_template("user.html")

@app.route("/create")
def create():
    return render_template("create.html")

@app.route("/read")
def read():
    return render_template("read.html")

@app.route("/update")
def update():
    return render_template("update.html")

@app.route("/delete")
def delete():
    return render_template("delete.html")

if __name__ == "__main__":
    app.run(debug=True)


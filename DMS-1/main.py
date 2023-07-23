from flask import Flask, request, render_template, redirect, url_for, session,flash,send_file
from pymongo import MongoClient
from datetime import datetime
from math import ceil
from flask import jsonify
import os,re
import hashlib
import json

from bson import ObjectId
from werkzeug.utils import secure_filename



app = Flask(__name__)
auth_token_user = '1234'
auth_token_admin='9999'
auth_token_superadmin='0000'
UPLOAD_FOLDER ='/home/rohini/Desktop/pinaca/DMS-1/uploads'

# app = Flask(__name__,static_url_path='/static')
app.secret_key = 'your_secret_key'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

client = MongoClient("mongodb://localhost:27017")
db = client["data"]
print("connected to mongo",client)

# Create the collections if they don't exist
if "registered_users" not in db.list_collection_names():
    db.create_collection("registered_users")
    print("Collection 'registered_users' created in database 'data'.")
registered_users = db["registered_users"]

if "login_attempts" not in db.list_collection_names():
    db.create_collection("login_attempts")
    print("Collection 'login_attempts' created in database 'data'.")
login_attempts = db["login_attempts"]


if "files" not in db.list_collection_names():
    db.create_collection("files")
    print("files collection is created")
files_collection=db["files"]

if "deleted_superadmin"  not in db.list_collection_names():
    db.create_collection("deleted_superadmin") 
    print("deleted_superadmin is created")
deleted_collection = db["deleted_superadmin"]





print(db.list_collection_names)



@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('log.html')


@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        # Retrieve JSON data from the request
        data = request.get_json()
        print(data)
        # Process registration form data
        Email_id = data.get('Email_id')
        print(Email_id)
        password = data.get('password')
        print(password)
        confirm_password = data.get('confirmPassword')
        print(confirm_password)
        auth_token = data.get('auth_token')
        print(auth_token)
        # Store the email_id and auth_token in the session
        session['email_id'] = Email_id
        session['auth_token'] = auth_token
        

        if Email_id is None or password is None or confirm_password is None or auth_token is None:
            error_message = "Please fill in all fields."
            return jsonify(error=error_message)

        elif not Email_id.endswith("@gmail.com"):
            error_message = "Invalid Email_id. Please enter valid email address."
            return jsonify(error=error_message)

        elif password != confirm_password:
            error_message = "Passwords do not match."
            return jsonify(error=error_message)

        else:
            # Determine the status based on the auth_token value
            if auth_token == "1234":
                status = "user"
            elif auth_token == "9999":
                status = "admin"
            elif auth_token == "0000":
                status = "superadmin"
            else:
                status = "unknown"
            # Store the registered user details in MongoDB
            registered_user = {
                'Email_id': Email_id,
                'password': password,
                'auth_token':auth_token,
                'status': status,
                'timestamp': datetime.now()
            }
            print("fetched")
            try:
                result = registered_users.insert_one(registered_user)
                print("Registered user inserted:", result.inserted_id)
                
            
                return jsonify(message="Registration successful! You can now login.")
            except Exception as e:
                print("Error inserting registered user:", e)
                return jsonify(error="An error occurred while registering the user.")
                
    
    return jsonify(error="Invalid request.")



    
                
          
@app.route('/login', methods=['POST'])        
def validate_credentials():
    data = request.get_json()
    Email_id = data['Email_id']
    password = data['password']
    matched_user = registered_users.find_one({'Email_id': Email_id, 'password': password})

    if matched_user:
        auth_token = matched_user.get("auth_token")
        status = matched_user.get("status")
        login_user = {
            'Email_id': Email_id,
            'auth_token': auth_token,
            'password': password,
            'status': status
        }

        try:
            existing_attempt = login_attempts.find_one({'Email_id': Email_id, 'password': password})
            if existing_attempt:
                login_attempts.update_one(
                    {'_id': existing_attempt['_id']},
                    {'$inc': {'count': 1}}
                )
                print('Login attempt count incremented')
            else:
                login_attempt = {
                    'Email_id': Email_id,
                    'password': password,
                    'timestamp': datetime.now(),
                    'count': 1,
                    'status': status
                }
                result = login_attempts.insert_one(login_attempt)
                print('New login attempt stored:', result.inserted_id)

            login_attempts.update_one(
                {'Email_id': Email_id},
                {'$set': login_user},
                upsert=True
            )

            session['Email_id'] = Email_id
            session['Auth_token'] = auth_token
            # session['Status'] = status
            print("session", session)

            return jsonify({"message": "Login successful","Email_id":Email_id,"password":password})
        except Exception as e:
            print('Error storing login attempt:', e)
            response = {'error': 'An error occurred while storing the login attempt'}
            return jsonify(response), 500
    else:
        return render_template('log.html')
    # error_message = "Invalid Email_id or password. Please try again."
    # return jsonify({"error": error_message}), 401

    


# Create the uploads folder if it doesn't exist
def create_upload_folder():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print("upload folder created")


# Generate a hash value for the uploaded file
def generate_file_name(filename):
    filename, extension = os.path.splitext(filename)
    hash_object = hashlib.md5(filename.encode())
    hash_value = hash_object.hexdigest()
    return f"{filename}_{hash_value}{extension}"


@app.route('/check-file-exists', methods=['POST'])
def check_file_exists():
    if request.method == 'POST':
        file_name = request.json.get('fileName')
        existing_file = files_collection.find_one({'file_name': file_name})
        return jsonify({'exists': True if existing_file else False})



@app.route('/upload-file', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'POST':
        try:
            file = request.files['file']
           

              
            # Save the new file and update the database
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    file_format = os.path.splitext(filename)[1][1:]
                    hashed_filename = generate_file_name(filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], hashed_filename)
                    file.save(file_path)

                    file_size_bytes = os.path.getsize(file_path)
                    file_size = file_size_bytes / 1024
                    current_time = datetime.now()

                    
                   
                    # For new file upload, create a new document in the database
                    casenumber = request.form.get('case_number')
                    casename = request.form.get('case_name')
                    uploaded_by = session.get('Email_id')
                    login_attempt = login_attempts.find_one({"Email_id": uploaded_by})
                    if login_attempt is None:
                        user_status = "unknown"
                    else:
                        user_status = login_attempt.get("status", "unknown")  # Get the status value if available

                    document = {
                            "case_number": casenumber,
                            "case_name": casename,
                            "file_name": hashed_filename,
                            "uploaded_by": uploaded_by,
                            "time_of_upload": current_time,
                            "format": file_format,
                            "size": file_size,
                            "status": user_status
                    }

                    result = files_collection.insert_one(document)
                    print("Document inserted:", result.inserted_id)

                    print("File uploaded/replaced and database updated successfully.")
                    return redirect('/display')  # Redirect after uploading/replacing the file

                except Exception as e:
                    print("Error uploading/replacing file:", str(e))
                    return render_template('upload.html', error_message="Error uploading/replacing file.")

            else:
                return render_template('upload.html', error_message="Invalid file.")

        except KeyError:
            return render_template('upload.html', error_message="File not found in the request.")

    return render_template('upload.html')

# @app.route('/replace-file', methods=['POST', 'GET'])
# def replace_file(request):
#     if request.method == 'POST':
#         # Get the uploaded file from the request
#         file = request.files['file']

#         # Get other form data like 'case_number' and 'case_name'
#         case_number = request.form['case_number']
#         case_name = request.form['case_name']

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    Email_id = data.get('Email_id')
    auth_token = data.get('auth_token')
    newPassword = data.get('newPassword')

    # Check if the email exists in the registered_user collection
    user = registered_users.find_one({'Email_id': Email_id})

    if user:
        # Check if the auth_token matches
        if user['auth_token'] == auth_token:
            # Update the password in the registered_user collection
            registered_users.update_one(
                {'Email_id': Email_id},
                {'$set': {'password': newPassword}}
            )
            return jsonify({'success': True, 'message': 'Password reset successful!'})
        else:
            return jsonify({'error': 'Invalid auth_token'})
    else:
        return jsonify({'error': 'Email not found'})





@app.route('/display', methods=['GET'])
def display():
    email_id = session.get('Email_id')
    
    # Check if the email ID is present in the session
    if email_id:
        login_attempt = login_attempts.find_one({'Email_id': email_id})
        if login_attempt:
           
            status = login_attempt.get('status')
            
            # Determine if the modified section should be displayed based on the user's status
            show_modified_section = (status == 'superadmin')
            
            # Fetch files based on the user's status
            if status == 'superadmin':
                # Fetch all files from the files collection
                file_details = files_collection.find({})
            elif status == 'admin':
                # Fetch files uploaded by admin and users
                file_details = files_collection.find({"$or": [{"status": "admin"}, {"status": "user"}]})
            else:
                # Fetch files uploaded by the current user only
                file_details = files_collection.find({"uploaded_by": email_id})

            files = []
            for file in file_details:
                casenumber = file.get("case_number")
                print("case number:",casenumber)
                casename = file.get("case_name")
                print("case name:",casename)
                file_name = file.get("file_name")
                print("filename:",file_name)
                # Remove the hash value from the file name
                # prefix = "_".join(file_name.split("_")[:-1])
                
                uploaded_by=file.get("status")
                datetime = file.get("time_of_upload")
                format = file.get("format")
                size = file.get("size")
                date = datetime.date()
                time = datetime.time()

                files.append({
                    "case_number": casenumber,
                    "case_name": casename,
                    "file_name":file_name,
                    "date": date,
                    "time": time,
                    "format": format,
                    "size": size,
                    "uploaded_by": uploaded_by,
                })
        

            return render_template('display.html', Email_id=email_id, files=files,show_modified_section=show_modified_section)

    # If the email ID is not present in the session or login attempts database, redirect to the login page
    return render_template('log.html')




    

@app.route('/view_file/<file_name>')
def view_file(file_name):
    # Get the logged-in user's email from the session
    logged_in_user_email = session.get('Email_id')

    if logged_in_user_email:
        # Fetch the user data from the login attempts collection
        user_data = login_attempts.find_one({"Email_id": logged_in_user_email})

        # Check if the user has access rights
        if user_data and user_data.get("status") in ["admin", "superadmin"]:
            # Construct the file path using the provided file name and the uploads folder
            uploads_folder = app.config['UPLOAD_FOLDER']
            file_path = os.path.join(uploads_folder, file_name)

            # Check if the file exists
            if os.path.isfile(file_path):
                return send_file(file_path)
            else:
                return "File not found"
        else:
            return "Access denied"
    else:
        return "User not logged in"






    
    
@app.route('/delete-files', methods=['POST'])
def delete_files():
    data = request.get_json()
    case_names = data.get('caseNames')

    # Check if the case names are present
    if case_names:
        try:
            for case_name in case_names:
                # Find the file in the "files" collection
                file = files_collection.find_one_and_delete({'case_name': case_name})

                if file:
                    # Update the status of the file to "deleted"
                    file['status'] = 'deleted'
                    # Move the document to the "deleted_superadmin_files" collection
                    deleted_collection.insert_one(file)

            return jsonify(message="Documents deleted successfully.")
        except Exception as e:
            return jsonify(error="An error occurred while deleting the documents.")
    else:
        return jsonify(error="Invalid request.")

# @app.route('/reupload', methods=['POST'])
# def reupload():
#     try:
#         data = request.get_json()
#         print(data)
#         file_name = data.get('file_name')
#         print("file",file_name)

#         if not file_name:
#             return jsonify({'error': 'File name not provided.'}), 400

#         existing_file = files_collection.find_one({'file_name': file_name})
#         print("old file",existing_file)

#         if existing_file:
#             # Remove the existing file
#             # existing_file_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_file['file_name'])
#             # os.remove(existing_file_path)

#             # Save the new file and update the database
#             file = request.files['file']
            
#             if file and allowed_file(file.filename):
#                 try:
#                     filename = secure_filename(file.filename)
#                     file_format = os.path.splitext(filename)[1][1:]  # Get the file extension
#                     hashed_filename = generate_file_name(filename)
#                     file_path = os.path.join(app.config['UPLOAD_FOLDER'], hashed_filename)
#                     file.save(file_path)

#                     file_size_bytes = os.path.getsize(file_path)
#                     current_time = datetime.now()
#                     print("ready to update")
#                     # Update the file details in the database
#                     files_collection.update_one(
#                         {'file_name': file_name},
#                         {'$set': {
#                             'file_name': hashed_filename,
#                             'time_of_upload': current_time,
#                             'format': file_format,
#                             'size': file_size_bytes,
#                             'new_file_superadmin': True
#                         }}
#                     )

#                     print("File replaced and database updated successfully.")
#                     return jsonify({'message': 'File replaced successfully.'}), 200

#                 except Exception as e:
#                     print("Error replacing file:", str(e))
#                     return jsonify({'error': 'Error replacing file.'}), 500

#             else:
#                 return jsonify({'error': 'Invalid file.'}), 400

#         else:
#             return jsonify({'error': 'File not found in the database.'}), 404

#     except Exception as e:
#         print("Error during re-upload:", str(e))
#         return jsonify({'error': 'An error occurred during re-upload.'}), 500
 

@app.route('/checkFilesInDB', methods=['POST'])
def check_files_in_db():
    data = request.get_json()
    file_names = data.get('fileNames', [])
    print("file from frontend",file_names)

    # Check if each file name exists in the MongoDB collection
    cursor = files_collection.find({"file_name": {"$in": file_names}})
    db_files = [doc["file_name"] for doc in cursor]
    print("file exists")
    
    # Check if all file names were found in the database
    all_files_exist = all(file_name in db_files for file_name in file_names)

    # Return the result as JSON
    return jsonify(exists=all_files_exist)

 


# @app.route('/replace-file', methods=['POST'])
# def replace_file():
#     try:
#         selected_file = request.files['selectedFile']
#         print("selected file received", selected_file)

#         file_names_json = request.form.get('fileNames')
#         file_names = json.loads(file_names_json) if file_names_json else []
#         print("file existing received from frontend", file_names)

#         if file_names:
#             for file_name in file_names:
#                 # Remove square brackets and double quotes from the file name
                
#                 file_name = file_names[0]
#                 file_name = file_name.strip()

#                 # Construct the query as a dictionary
#                 query = {"file_name": file_name}

#                 existing_file = files_collection.find_one(query)
#                 print("existing file", existing_file)




#                 if existing_file:
#                     print("yes")
#                     # Remove the existing file
#                     existing_file_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_file['file_name'])
#                     os.remove(existing_file_path)

#                     # Save the new file and update the database
#                     if selected_file and allowed_file(selected_file.filename):
#                         try:
#                             filename = secure_filename(selected_file.filename)
#                             file_format = os.path.splitext(filename)[1][1:]  # Get the file extension
#                             hashed_filename = generate_file_name(filename)
#                             file_path = os.path.join(app.config['UPLOAD_FOLDER'], hashed_filename)
#                             selected_file.save(file_path)

#                             file_size_bytes = os.path.getsize(file_path)
#                             current_time = datetime.now()

#                             # Update the file details in the database
#                             files_collection.update_one(
#                                 {'file_name': file_name},
#                                 {'$set': {
#                                     'file_name': hashed_filename,
#                                     'time_of_upload': current_time,
#                                     'format': file_format,
#                                     'size': file_size_bytes,
#                                     'superadmin_updated': True,
#                                     'old_file':file_name,
#                                 }}
#                             )

#                             print(f"File with name {file_name} replaced and database updated successfully.")
#                             # You may return a response here if needed

#                         except Exception as e:
#                             print("Error replacing file:", str(e))
#                             return jsonify({'error': 'Error replacing file.'}), 500

#                     else:
#                         return jsonify({'error': 'Invalid file.'}), 400

#                 else:
#                     return jsonify({'error': f'File with name {file_name} not found in the database.'}), 404

#             return jsonify({'message': 'All files replaced successfully.'}), 200

#         else:
#             return jsonify({'error': 'No file names received from the frontend.'}), 400

#     except Exception as e:
#         print("Error during re-upload:", str(e))
#         return jsonify({'error': 'An error occurred during re-upload.'}), 500
@app.route('/download_file/<fileNames>')
def download_file(fileNames):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], fileNames)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return f"File '{fileNames}' not found.", 404

@app.route('/replace-file', methods=['POST'])
def replace_file():
    try:
        selected_files = request.files.getlist('selectedFiles')  # Get a list of selected files
        print("Selected files",selected_files)

        file_names_json = request.form.get('fileNames')
        file_names = json.loads(file_names_json) if file_names_json else []
        print("file names from frontend",file_names)

        if file_names:
            for idx, file_name in enumerate(file_names):
                file_name = file_name.strip()

                # Construct the query as a dictionary
                query = {"file_name": file_name}

                existing_file = files_collection.find_one(query)

                if existing_file:
                    # Remove the existing file
                    existing_file_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_file['file_name'])
                    os.remove(existing_file_path)

                    # Save the new file and update the database
                    if idx < len(selected_files) and allowed_file(selected_files[idx].filename):
                        try:
                            selected_file = selected_files[idx]
                            filename = secure_filename(selected_file.filename)
                            file_format = os.path.splitext(filename)[1][1:]  # Get the file extension
                            hashed_filename = generate_file_name(filename)
                            file_path = os.path.join(app.config['UPLOAD_FOLDER'], hashed_filename)
                            selected_file.save(file_path)

                            file_size_bytes = os.path.getsize(file_path)
                            current_time = datetime.now()

                            # Update the file details in the database
                            files_collection.update_one(
                                {'file_name': file_name},
                                {'$set': {
                                    'file_name': hashed_filename,
                                    'time_of_upload': current_time,
                                    'format': file_format,
                                    'size': file_size_bytes,
                                    'superadmin_updated': True,
                                    'old_file': file_name,
                                }}
                            )

                            print(f"File with name {file_name} replaced and database updated successfully.")
                            # You may return a response here if needed

                        except Exception as e:
                            print("Error replacing file:", str(e))
                            return jsonify({'error': 'Error replacing file.'}), 500

                    else:
                        return jsonify({'error': f'Invalid file or no file selected for {file_name}.'}), 400

                else:
                    return jsonify({'error': f'File with name {file_name} not found in the database.'}), 404

            return jsonify({'message': 'All files replaced successfully.'}), 200

        else:
            return jsonify({'error': 'No file names received from the frontend.'}), 400

    except Exception as e:
        print("Error during re-upload:", str(e))
        return jsonify({'error': 'An error occurred during re-upload.'}), 500
               


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port="9999")
    app.register_blueprint(display)


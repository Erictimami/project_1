from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
import re #means regex for regular expression. using to sort( adding a long string after the real password before hashing )
from flask_bcrypt import Bcrypt    #for salting and hashing the password    
       
# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

#opening the app using Flask
app = Flask(__name__)
bcrypt = Bcrypt(app) 
app.secret_key="dajlhayjsvsckjfk" #secret key for opening the session

@app.route('/log_off')
def log_off():
    session.clear()
    flash("You have been logged out", 'logged_out')
    return redirect('/')


@app.route('/')
def index():  
    if ('logged' or 'id') not in session:
        session['logged']=False
        session['id']=0
    elif session['logged']==None:
        flash("You have been logged out", 'logged_out')
    return render_template("index.html")


@app.route('/process_registration', methods=['POST'])
def process_registration():
    
    if request.method != 'POST' or session['logged'] == True:
        return redirect('/')

    valid_form_ok = True
    # Let's add validation rules

    if (len(request.form['first_name']) <= 2) or (bool(re.search(r'\d', request.form['first_name'])) == True) :   #check if at least 2 characters and if only the letter by using REGEX
        flash("First name must contain at least two and contain only letters", 'first_name')
        valid_form_ok=False

    if (len(request.form['last_name']) <= 2) or (bool(re.search(r'\d', request.form['last_name'])) == True) :
        flash("Last name must contain at least two and contain only letters", 'last_name')
        valid_form_ok=False

    if not EMAIL_REGEX.match(request.form['email']):  #checking validation email
        flash("Invalid email address!", 'email')
        valid_form_ok=False
    else:
        mysql = connectToMySQL('simple_wall_db')
        email_query = "SELECT * FROM users WHERE users.email LIKE %(new_email)s;"
        data = {"new_email": request.form['email']}
        if mysql.query_db(email_query,data):
            flash("This email is already used by another user", 'email')
            valid_form_ok=False

    if (len(request.form['password']) < 8) or (len(request.form['password']) > 15):
        flash("Password must contain a number, a capital letter, and be between 8-15 characters", 'password')
        valid_form_ok=False
    elif request.form['password'] != request.form['confirm_pw']:
        flash("Passwords must match", 'confirm_pw')
        valid_form_ok=False

    if valid_form_ok == False :
        if '_flashes' in session.keys():
            session['first_name'], session['last_name'], session['email'] = request.form['first_name'], request.form['last_name'], request.form['email']
            return redirect('/')
    else:
        # include some logic to validate user input before adding them to the database!
        # create the hash
        password_hash = bcrypt.generate_password_hash(request.form['password'])  
        print('=====================================================',password_hash)  
        # be sure you set up your database so it can store password hashes this long (60 characters)

        mysql = connectToMySQL('simple_wall_db')
        insert_query = "INSERT INTO users (first_name, last_name, email, password, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, now());"
        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['email'],
            "password": password_hash
            }
        print("error here")
        id_new_user=mysql.query_db(insert_query, data)
        print(id_new_user)
        
        if ('logged' or 'id') not in session:
            session['logged']= True
            session['id']=id_new_user
            return redirect('/wall')
        else:
            session['logged']= True
            session['id']=id_new_user
            return redirect('/wall')

@app.route('/process_login', methods=['POST'])
def process_loggin():

    if request.method != 'POST' or session['logged'] == True:
        return redirect('/')

    if not EMAIL_REGEX.match(request.form['email']):  #checking validation email
        flash("Email and/or password are INVALID!", 'login')
        return redirect('/')
    else:
        mysql = connectToMySQL('simple_wall_db')
        query = "SELECT users.email, users.password, users.id FROM users WHERE users.email=%(new_email)s;"
        data = {"new_email": request.form['email'].strip().lower() }

        print('$$$$$$$$$$$$$$$$$$$$$$$$$$ new_email', data)
        result_data = mysql.query_db(query,data) 
        print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!result_data:', result_data)
        if not result_data:
            flash("Email and/or password are INVALID!", 'login') #this email never registered
            return redirect('/')
        elif bcrypt.check_password_hash(result_data[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@', result_data)
            session['id'] = result_data[0]['id']
            session['logged']=True
            return redirect('/wall')
    flash("Email and/or password are INVALID!", 'login')
    return redirect('/')






@app.route('/wall')
def wall():  

    if request.method != 'GET' or session['logged'] != True:
        return redirect('/')

    # display msg side ####
    #total msg received
    mysql = connectToMySQL('simple_wall_db')
    query= "SELECT users.first_name, COUNT(messages.message) AS count_msg_r FROM users JOIN messages ON users.id = messages.users_r_id WHERE users.id=%(id)s GROUP BY users.id"
    # data = {"id": session['id']}
    data = {"id": session['id']}
    result_count_msg_r=mysql.query_db(query,data)
    print('+++++++++++++++result_count_msg_r++++++++++++++++++++++', result_count_msg_r)
    # print('$$$$$$$$$$$$$$result_count_msg_r[0][count_msg_r]$$$$$$$$$$$$$$$$$$', result_count_msg_r[0]['count_msg_r'])
    if len(result_count_msg_r)==0:
        count_msg_r=0
        first_name=''
    else:
        count_msg_r=result_count_msg_r[0]['count_msg_r']
        first_name=result_count_msg_r[0]['first_name']
   
    # display senders and their msg
    mysql = connectToMySQL('simple_wall_db')
    query= "SELECT u2.id, u1.first_name AS sender, messages.id AS msg_id, messages.message FROM users  AS u1 JOIN messages ON u1.id =messages.users_s_id JOIN users AS u2 ON messages.users_r_id=u2.id WHERE u2.id = %(id)s"
    result_s_msg=mysql.query_db(query,data)
    print('*************result_s_msg********************', result_s_msg)


    # print('+==============result_s_msg[0][sender]=======================', result_s_msg[0]['sender'])

    # Send a message #####
    # first name of others users
    mysql = connectToMySQL('simple_wall_db')
    query= "SELECT users.first_name, users.id as o_u_id FROM users WHERE users.id != %(id)s"
    result_others_users=mysql.query_db(query,data)
    print(len(result_others_users))
    print('hhhhhhhhhhhhhresult_others_usershhhhhhhhhhhhhhhhhhhh', result_others_users)
    print('hhhhhhhhhhhhhhhhresult_others_users[0][o_u_id]hhhhhhhhhhhhhhhhh', result_others_users[0]['o_u_id'])

    

    #total msg send by the user's account
    mysql = connectToMySQL('simple_wall_db')
    query= "SELECT COUNT(messages.message) as count_msg_s FROM users JOIN messages ON users.id = messages.users_s_id WHERE users.id=%(id)s GROUP BY users.id"
    result_count_msg_s=mysql.query_db(query,data)
    # print('**************result_count_msg_s*******************', result_count_msg_s)

    if len(result_count_msg_s)==0:
        count_msg_s=0
    else:
        count_msg_s=result_count_msg_s[0]['count_msg_s']

    return render_template("wall.html", first_name=first_name, count_msg_r=count_msg_r, result_s_msg=result_s_msg, count_msg_s=count_msg_s, result_others_users=result_others_users, num_o_u=len(result_others_users))



@app.route('/send/<o_u_id>', methods=['POST'])
def send(o_u_id):  

    if request.method != 'POST' or session['logged'] != True:
        return redirect('/')
     
    print('^^^^^Testingggggggggg^^^^^^^^^^^^^^^^^^^^^', request.form)

    data = {
        'users_r_id': o_u_id,
        'users_s_id': session['id'],
        'message': request.form['message']
    }
    print('#######################################', request.form['message'])
    query= "INSERT INTO messages (message, users_s_id, users_r_id, created_at) VALUES (%(message)s, %(users_s_id)s, %(users_r_id)s, Now());"
    mysql = connectToMySQL('simple_wall_db')
    mysql.query_db(query, data)
    print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
    return redirect('/wall')


@app.route('/delete/<msg_id>')
def delete(msg_id):  
    if session['logged'] != True:
        return redirect('/')
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    query = "DELETE FROM messages WHERE id = %(msg_id)s"
    data = {
        'msg_id': msg_id
    }
    mysql = connectToMySQL('simple_wall_db')
    mysql.query_db(query, data)
    return redirect('/wall')


if __name__ == "__main__":
    app.run(debug = True)



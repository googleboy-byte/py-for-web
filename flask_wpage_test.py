from flask import Flask, flash, redirect, render_template, request, session, abort
import os

app = Flask(__name__)

#<!-- begin wwww.htmlcommentbox.com -->
#<div id="HCB_comment_box"><a href="http://www.htmlcommentbox.com">Comment Form</a> is loading comments...</div>
#<link rel="stylesheet" type="text/css" href="https://www.htmlcommentbox.com/static/skins/bootstrap/twitter-bootstrap.css?v=0" />
#<script type="text/javascript" id="hcb"> /*<!--*/ if(!window.hcb_user){hcb_user={};} (function(){var s=document.createElement("script"), l=hcb_user.PAGE || (""+window.location).replace(/'/g,"%27"), h="https://www.htmlcommentbox.com";s.setAttribute("type","text/javascript");s.setAttribute("src", h+"/jread?page="+encodeURIComponent(l).replace("+","%2B")+"&mod=%241%24wq1rdBcg%24zk.oD%2Fauu5LJn46MKVU9S0"+"&opts=16862&num=10&ts=1596278313095");if (typeof s!="undefined") document.getElementsByTagName("head")[0].appendChild(s);})(); /*-->*/ </script>
#<!-- end www.htmlcommentbox.com -->

@app.route("/")

def index():
	if not session.get('logged_in'):
		return render_template('login.html')
	else:
		return render_template('main.html')
	#return render_template('main.html')

@app.route("/login", methods=['POST'])

def login():
	if request.form['password'] == 'password' and request.form['username'] == 'admin':
		session['logged_in'] = True
		return index()
	else:
		flash('Wrong User or Password')
		return index()

if __name__ == "__main__":
	app.secret_key = os.urandom(12)
	app.run(debug=True, host='0.0.0.0', port=80)

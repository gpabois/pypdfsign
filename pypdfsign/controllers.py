from flask import Flask, session
from flask_login import login_user, login_required, logout_user, current_user

from .cert  import gen_cert, dump_cert
from .forms import LoginForm, CreateCertForm, RegisterUserForm
from .models import db, users, certs_pks
from .files  import store

import uuid

from urllib.parse import urlparse, urljoin
from flask import render_template, redirect, request, url_for, abort

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def init_app(app):
    @app.route('/', methods=['GET'])
    def index():
        return render_template('index.html')

    @app.route('/users/register', methods=['GET', 'POST'])
    def register_user():
        form = RegisterUserForm()
        
        if form.validate_on_submit():
            db.session.add(users(form.email.data, form.password.data))
            db.session.commit()
            return redirect(next or url_for('login'))
        
        return render_template('register_user.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            # Login and validate the user.
            # user should be an instance of your `User` class
            login_user(form.user)

            flash('Logged in successfully.')

            next = request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            if not is_safe_url(next):
                return abort(400)

            return redirect(next or url_for('index'))
            
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/certs', methods=['GET'])
    @login_required
    def list_certs():
        pass

    @app.route('/certs/create', methods=['GET', 'POST'])
    @login_required
    def create_cert():
        form = CreateCertForm()
        
        if form.validate_on_submit():
            common_name = form.common_name.data
            pin_code = form.pin_code.data
            
            country_name = app.config['DEFAULT_CERT_COUNTRY_NAME']
            locality_name = app.config['DEFAULT_CERT_LOCALITY_NAME']
            state_or_province_name = app.config['DEFAULT_CERT_STATE_OR_PROVINCE_NAME']
            organization_name = app.config['DEFAULT_CERT_ORGANIZATION_NAME']
            organization_unit_name = app.config['DEFAULT_CERT_ORGANIZATION_UNIT_NAME']
            
            (cert, pk) = gen_cert(current_user.email, common_name, country_name, locality_name, state_or_province_name, organization_name, organization_unit_name, 0)
            (cert, pk) = dump_cert((cert, pk))
            
            certs_dir   = app.config['CERTS_DIRECTORY']
            private_dir = app.config['PRIVATE_DIRECTORY']
            
            cert_file_id = str(uuid.uuid4())
            pk_file_id = str(uuid.uuid4())
            
            store("{}.pem".format(cert_file_id), cert, certs_dir)
            store("{}.pem".format(pk_file_id), pk, pk_file_id)
            
            db.session.add(certs_pks(current_user.id, cert_file_id, pk_file_id, pin_code))
            db.session.commit()
            
            return redirect(url_for('list_certs'))
        
        return render_template('login.html', form=form)  
            
    
    
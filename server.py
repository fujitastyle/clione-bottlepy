import bottle
from bottle import get, post, route, request, response, abort, static_file
from bottle.ext import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, Sequence, String, ARRAY, desc
from sqlalchemy.ext.declarative import declarative_base
import json
import collections
import datetime
import pytz

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
import requests
import base64


PROTOCOL='https'
HOSTNAME='22.misoni.club'
URL=PROTOCOL+'://'+HOSTNAME
PORT=5200
SECRET='secret'
DBTYPE='sqlite'
DBNAME=''
DBUSERNAME=''
DBPASSWORD=''

Base = declarative_base()
engine = create_engine('sqlite:///server.db', echo=False)

app = bottle.Bottle()
plugin = sqlalchemy.Plugin(
    engine, # SQLAlchemy engine created with create_engine function.
    Base.metadata, # SQLAlchemy metadata, required only if create=True.
    keyword='db', # Keyword used to inject session database in a route (default 'db').
    create=True, # If it is true, execute `metadata.create_all(engine)` when plugin is applied (default False).
    commit=True, # If it is true, plugin commit changes after route is executed (default True).
    use_kwargs=False # If it is true and keyword is not defined, plugin uses **kwargs argument to inject session database (default False).
)

app.install(plugin)



class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)
    fullname = Column(String)
    summary = Column(String)
    privatekey = Column(String)
    publickey = Column(String)
    following = Column(ARRAY(String))
    followers = Column(ARRAY(String))

    def __init__(self, username, password, fullname, summary, privatekey, publickey):
        self.username = username
        self.password = password
        self.fullname = fullname
        self.summary = summary
        self.privatekey = privatekey
        self.publickey = publickey

    def __repr__(self):
        return "<User('%d', '%s', '%s', '%s', '%s')>" % (self.id, self.username, self.password, self.fullname, self.summary)

class Post(Base):
    __tablename__ = 'post'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    posttext = Column(String)
    postdate = Column(String)
    liked = Column(Integer)

    def __init__(self, username, posttext, postdate, liked):
        self.username = username
        self.posttext = posttext
        self.postdate = postdate
        self.liked = liked

    def __repr__(self):
        return "<Post('%d', '%s', '%s', '%s', %d)>" % (self.id, self.username, self.posttext, self.postdate, self.liked)


##web
@app.route('/')
def index(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if not userid:
        return '''
            <p>[clione] activitypub test server
            <hr>
            <p><a href="/auth/login">login</a></p>
            <p><a href="/auth/register">register</a></p>
        '''
    user = db.query(User).filter_by(id=userid).first()
    if not user:
        return '''
            <p>[clione] activitypub test server
            <hr>
            <p><a href="/auth/login">login</a></p>
            <p><a href="/auth/register">register</a></p>
        '''

    return '''
        <p>[clione] activitypub test server
        <hr>
        <p><a href="/web/user">user</a></p>
        <p><a href="/web/post">post</a></p>
        <p><a href="/auth/logout">logout</a></p>
    '''

@app.route('/favicon.ico')
def favionico():
    return static_file('favicon.ico', root='./')

@app.route('/icon.png')
def iconpng():
    return static_file('icon.png', root='./')

@app.get('/web/user')
def user(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if not userid:
        return 'invalid session'
    user = db.query(User).filter_by(id=userid).first()
    if not user:
        return 'invalid user'
    return '''
        <img src="/icon.png">
        <p>username@hostname: {username}@{hostname}</p>
        <p>fullname: {fullname}</p>
        <p>summary: {summary}</p>
        <hr>
        <form action="/web/user" method="post">
            <p>fullname: <input name="fullname" type="text" /></p>
            <p>summary: <input name="summary" type="text" /><p>
            <p><input value="update user(未実装)" type="submit" /></p>
        </form>
    '''.format(username=user.username, hostname=HOSTNAME, fullname=user.fullname, summary=user.summary)

@app.post('/web/user')
def do_user(db):
    #update user profile
    pass

@app.get('/web/post')
def post(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if not userid:
        return 'invalid session'
    user = db.query(User).filter_by(id=userid).first()
    if not user:
        return 'invalid user'
    return '''
        <form action="/web/post" method="post">
            posttext: <input name="posttext" type="text" />
            <input value="new post" type="submit" />
        </form>
    '''

@app.post('/web/post')
def do_post(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if not userid:
        return 'invalid session'
    user = db.query(User).filter_by(id=userid).first()
    if not user:
        return 'invalid user'
    username = user.username
    posttext = request.forms.get('posttext')
    if not posttext:
        return 'this posttext is empty'
    postdate = datetime.datetime.now(pytz.timezone('Asia/Tokyo')).isoformat(timespec='seconds')
    post = Post(username=username, posttext=posttext, postdate=postdate, liked=0)
    db.add(post)
    post = db.query(Post).order_by(desc(Post.id)).first()
    note = collections.OrderedDict()
    note = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'type': 'Note',
        'id': URL+'/activitypub/'+username+'/'+str(post.id),
        'attributedTo': URL+'/activitypub/'+username,
        'content': posttext,
        'published': postdate,
        'to': [
            'https://www.w3.org/ns/activitystreams#Public',
        ]
    }
    create = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'type': 'Create',
        'object': note
    }
    return 'done: '+posttext

@app.get('/web/users/<userid>')
def users(db, userid):
    if not db.query(User).filter_by(id=userid).scalar():
        return 'this user id is not found'
    user = db.query(User).filter_by(id=userid).first()
    return 'username: '+user.username

@app.get('/web/posts/<postid>')
def posts(db, postid):
    if not db.query(Post).filter_by(id=postid).scalar():
        return 'this post id is not found'
    post = db.query(Post).filter_by(id=postid).first()
    return 'posttext: '+post.posttext

##auth
@app.get('/auth/register')
def register():
    return '''
        <form action="/auth/register" method="post">
            username: <input name="username" type="text" />
            password: <input name="password" type="password" />
            fullname: <input name="fullname" type="text" />
            summary: <input name="summary" type="text" />
            <input value="register" type="submit" />
        </form>
    '''

@app.post('/auth/register')
def do_register(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    fullname = request.forms.get('fullname')
    summary = request.forms.get('summary')
    if not username:
        return 'this username is empty'
    if not username.isalnum():
        return 'this username contains characters that cannot be used'
    if db.query(User).filter_by(username=username).scalar():
        return 'this username is already used'
    if not password:
        return 'this password is empty'
    if not password.isalnum():
        return 'this password contains characters that cannot be used'
    if not password:
        return 'this fullname is empty'

    rsa = RSA.generate(2048, Random.new().read)
    privatekey = rsa.exportKey(format='PEM').decode()
    publickey = rsa.publickey().exportKey().decode()

    user = User(
        username=username,
        password=password,
        fullname=fullname,
        summary=summary,
        privatekey=privatekey,
        publickey=publickey
    )
    db.add(user)
    return '''
        register done
        <p><a href="/auth/login">login</a></p>
    '''

@app.get('/auth/login')
def login():
    return '''
        <form action="/auth/login" method="post">
            username: <input name="username" type="text" />
            password: <input name="password" type="password" />
            <input value="login" type="submit" />
        </form>
    '''

@app.post('/auth/login')
def do_login(db):
    username = request.forms.get('username')
    password = request.forms.get('password')
    if not username:
        return 'this username is empty'
    if not username.isalnum():
        return 'this username contains characters that cannot be used'
    if not password:
        return 'this password is empty'
    if not password.isalnum():
        return 'this password contains characters that cannot be used'
    if not db.query(User).filter_by(username=username).scalar():
        return 'this username is not found'
    user = db.query(User).filter_by(username=username).first()
    if user.password != password:
        return 'this password is wrong'
    response.set_cookie('userid', user.id, secret=SECRET, path='/')
    return '''
        login done
        <p><a href="/">top</a></p>
    '''

@app.route('/auth/logout')
def logout():
    response.delete_cookie('userid', path='/')
    return '''
        logout done
        <p><a href="/">top</a></p>
    '''

##well-known
@app.get('/.well-known/host-meta')
def hostmeta():
    response.headers['Content-Type'] = 'appliation/xrd+xml'
    return '''
        <?xml version="1.0" encoding="UTF-8"/>
        <XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
            <Link rel="lrdd" type="application/xrd+xml" template="{URL}/.well-known/webfinger?resource={{uri}}"/>
        </XRD>
    '''.format(URL=URL)

@app.get('/.well-known/webfinger')
def webfinger(db):
    resource = request.query.resource
    if not resource:
        abort(404)
    #format cheack 're' wo tukae
    if not resource.startswith('acct:'):
        abort(404)
    if resource.count(':') != 1:
        abort(404)
    if resource.count('@') != 1:
        abort(404)
    username = resource.split(':')[1].split('@')[0]
    hostname = resource.split(':')[1].split('@')[1]
    if hostname != HOSTNAME:
        abort(404)
    if not db.query(User).filter_by(username=username).scalar():
        abort(404)
    user = db.query(User).filter_by(username=username).first()
    webfinger = collections.OrderedDict()
    webfinger = {
        'subject': resource,
        'links': [
            {
                'rel': 'self',
                'type': 'application/activity+json',
                'href': URL+'/activitypub/'+user.username
            }
        ]
    }
    response.headers['Content-Type'] = 'application/jrd+json'
    return json.dumps(webfinger, indent=2)

@app.get('/.well-known/nodeinfo')
def nodeinfo():
    pass

##activitypub
@app.get('/activitypub/<username>')
def person(db, username):
    if not db.query(User).filter_by(username=username).scalar():
        abort(404)
    user = db.query(User).filter_by(username=username).first()
    person = collections.OrderedDict()
    person = {
        '@context': [
            'https://www.w3.org/ns/activitystreams',
            'https://w3id.org/security/v1'
        ],
        'id': URL+'/activitypub/'+username,
        'type': 'Person',
        'inbox': URL+'/activitypub/'+username+'/inbox',
        'outbox': URL+'/activitypub/'+username+'/outbox',
        'preferredUsername': username,
        'name': user.fullname,
        'sumarry': user.summary,
        'url': URL+'/web/users/'+str(user.id),
        'manuallyApprovesFollowers': False,
        'discoverable': True,
        'publicKey': {
            'id': URL+'/activitypub/'+username,
            'owner': URL+'/activitypub/'+username,
            'publicKeyPem': user.publickey
        },
        'attachment': {
            'type': 'PropertyValue',
            'na': 'clione',
            'value': URL
        },
        'icon': {
            'type': 'Image',
            'mediaType': 'image/png',
            'url': URL+'/icon.png'
        },
        'endpoints': {
            'sharedInbox': URL+'/inbox'
        }
    }
    response.headers['Content-Type'] = 'application/activity+json'
    return json.dumps(person, indent=2)


@app.get('/activitypub/<username>/<noteid>')
def note(db, username, noteid):
    if not db.query(Post).filter_by(id=postid).scalar():
        return 'this post id is not found'
    post = db.query(Post).filter_by(id=postid).first()
    if post.username != username:
        abort(404)
    note = collections.OrderedDict()
    note = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        'type': 'Note',
        'id': URL+'/activitypub/'+username+'/'+noteid,
        'attributedTo': URL+'/activitypub/'+username,
        'content': post.posttext,
        'published': post.postdate,
        'to': [
            'https://www.w3.org/ns/activitystreams#Public',
        ]
    }
    response.headers['Content-Type'] = 'application/activity+json'
    return json.dumps(note, indent=2)

@app.post('/activitypub/<username>/inbox')
def user_inbox(db, username):
    if request.headers['Content-Type'] != 'application/activity+json':
        abort(404)
    inbox = json.loads(request.body.read().decode())
    print(inbox)

    if not dict(inbox):
        abort(404)
    print(inbox['type'])
    if inbox['type'] == 'Follow':
        if not db.query(User).filter_by(username=username).scalar():
            abort(404)
        user = db.query(User).filter_by(username=username).first()
        remote_actor_url = inbox['actor']
        res = requests.get(remote_actor_url,headers={'Accept':'application/activity+json'})
        if res.status_code != 200:
            abort(404)
        remote_inbox_url = res.json()['inbox']
        remote_hostname = remote_inbox_url.split('/')[2]
        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Accept',
            'actor': URL+'/activitypub/'+username,
            'object': inbox
        }

        #http header signature---
        date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        signed_string = 'date: {date}'.format(date=date)
        signer = PKCS1_v1_5.new(RSA.importKey(user.privatekey.encode()))
        signature = base64.b64encode(signer.sign(SHA256.new(signed_string.encode()))).decode()
        headers = {
            'date': date,
            'signature': 'keyId="'+URL+'/activitypub/'+username+'",algorithm="rsa-sha256",signature="'+signature+'"',
            'Content-Type': 'application/activity+json'
        }
        #---http header signature
        res = requests.post(remote_inbox_url, json=accept, headers=headers)
        if res.status_code != 202:
            abort(401)
        return bottle.Response(status=201)

    if inbox['type'] == 'Undo':
        if not db.query(User).filter_by(username=username).scalar():
            abort(404)
        user = db.query(User).filter_by(username=username).first()
        remote_actor_url = inbox['actor']
        res = requests.get(remote_actor_url,headers={'Accept':'application/activity+json'})
        if res.status_code != 200:
            abort(404)
        remote_inbox_url = res.json()['inbox']
        remote_hostname = remote_inbox_url.split('/')[2]
        accept = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'type': 'Accept',
            'actor': URL+'/activitypub/'+username,
            'object': inbox
        }
        print(accept)
        #http header signature---
        date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        signed_string = 'date: {date}'.format(date=date)
        signer = PKCS1_v1_5.new(RSA.importKey(user.privatekey.encode()))
        signature = base64.b64encode(signer.sign(SHA256.new(signed_string.encode()))).decode()
        headers = {
            'date': date,
            'signature': 'keyId="'+URL+'/activitypub/'+username+'",algorithm="rsa-sha256",signature="'+signature+'"',
            'Content-Type': 'application/activity+json'
        }
        #---http header signature
        res = requests.post(remote_inbox_url, json=accept, headers=headers)
        if res.status_code != 202:
            abort(401)
        return bottle.Response(status=201)


@app.get('/activitypub/<username>/outbox')
def user_outbox(db, username):
    if not db.query(User).filter_by(username=username).scalar():
        abort(404)
    page = request.query.page
    if page != 'true':
        outbox = {
            '@context': 'https://www.w3.org/ns/activitystreams',
            'id': URL+'/activitypub/'+username+'/outbox',
            'type': 'OrderedCollection',
            'totalItems': db.query(Post).filter_by(username=username).count(),
            'first': URL+'/activitypub/'+username+'/outbox?page=true',
            'last': URL+'/activitypub/'+username+'/outbox?min_id=0&page=true'
        }
    else:
        #notes return
        minid = request.query.min_id
        outbox = ''

    response.headers['Content-Type'] = 'application/activity+json'
    return json.dumps(outbox, indent=2)

#omaginai !!!
app.run(host='localhost', port=8080, debug=True, reloader=True)

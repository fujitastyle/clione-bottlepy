import bottle
from bottle import get, post, route, request, response, abort, static_file
from bottle.ext import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, Sequence, String
from sqlalchemy.ext.declarative import declarative_base
import json
import collections
import datetime
import pytz
from Crypto.PublicKey import RSA
from Crypto import Random

PROTOCOL='https'
HOSTNAME='test'
URL=PROTOCOL+'://'+HOSTNAME
PORT=5200
SECRET='secret'
DBTYPE='sqlite'
DBNAME=''
DBUSERNAME=''
DBPASSWORD=''

Base = declarative_base()
engine = create_engine('sqlite:///server.db', echo=True)

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

    def __init__(self, username, posttext, postdate):
        self.username = username
        self.posttext = posttext
        self.postdate = postdate

    def __repr__(self):
        return "<Post('%d', '%s', '%s', '%s')>" % (self.id, self.username, self.posttext, self.postdate)

##web
@app.route('/')
def index(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if userid:
        user = db.query(User).filter_by(id=userid).first()
        if user:
            return user.username
    return "Clione"

@app.route('/favicon.ico')
def favionico():
    return static_file('favicon.ico', root='./')

@app.get('/web/user')
def user(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if not userid:
        return "invalid session"
    user = db.query(User).filter_by(id=userid).first()
    if not user:
        return "invalid user"
    return "username:"+user.username+' fullname:'+user.fullname+' summary:'+user.summary

@app.post('/web/user')
def do_user(db):
    #update user profile
    pass

@app.get('/web/post')
def post(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if userid:
        user = db.query(User).filter_by(id=userid).first()
        if user:
            return '''
                <form action="/web/post" method="post">
                    posttet: <input name="posttext" type="text" />
                    <input value="post" type="submit" />
                </form>
            '''
    return "login needed"

@app.post('/web/post')
def do_post(db):
    userid = request.get_cookie('userid', secret=SECRET)
    if not userid:
        return "invalid session"
    user = db.query(User).filter_by(id=userid).first()
    if not user:
        return "invalid user"
    username = user.username
    posttext = request.forms.get('posttext')
    if not posttext:
        return "this posttext is empty"
    postdate = datetime.datetime.now(pytz.timezone('Asia/Tokyo')).isoformat(timespec='seconds')
    post = Post(username=username, posttext=posttext, postdate=postdate)
    db.add(post)
    return "post done : "+posttext

@app.get('/web/users/<userid>')
def users(db, userid):
    if not db.query(User).filter_by(id=userid).scalar():
        return "this user id is not found"
    user = db.query(User).filter_by(id=userid).first()
    return "username: "+user.username

@app.get('/web/posts/<postid>')
def posts(db, postid):
    if not db.query(Post).filter_by(id=postid).scalar():
        return "this post id is not found"
    post = db.query(Post).filter_by(id=postid).first()
    return "posttext: "+post.posttext

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
        return "this username is empty"
    if not username.isalnum():
        return "this username contains characters that cannot be used"
    if db.query(User).filter_by(username=username).scalar():
        return "this username is already used"
    if not password:
        return "this password is empty"
    if not password.isalnum():
        return "this password contains characters that cannot be used"
    if not password:
        return "this fullname is empty"
    
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
    return "register done"

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
        return "this username is empty"
    if not username.isalnum():
        return "this username contains characters that cannot be used"
    if not password:
        return "this password is empty"
    if not password.isalnum():
        return "this password contains characters that cannot be used"
    if not db.query(User).filter_by(username=username).scalar():
        return "this username is not found"
    user = db.query(User).filter_by(username=username).first()
    if not user.password == password:
        return "this password is wrong"
    print(user.id)
    response.set_cookie('userid', user.id, secret=SECRET, path='/')
    return "login done"

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
    print(resource)
    if not resource:
        abort(404)
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
        "subject": resource,
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": URL+'/activitypub/'+user.username
            }
        ]
    }
    response.headers['Content-Type'] = 'appliation/jrd+json'
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
        'type': 'Person',
        'id': URL+'/activitypub/'+user.username,
        'name': user.fullname,
        'preferredUsername': user.username,
        'sumarry': user.summary,
        'inbox': URL+'/activitypub/inbox',
        'outbox': URL+'/activitypub/outbox',
        'url': URL+'/users/'+str(user.id),
        "publicKey": {
            "id": URL+'/activitypub/'+user.username,
            "owner": URL+'/activitypub/'+user.username,
            "publicKeyPem": user.publickey
        },
    }
    response.headers['Content-Type'] = 'appliation/activity+json'
    return json.dumps(person, indent=2)

@app.post('/activitypub/inbox')
def inbox():
    contentType = request.headers['Content-Type']
    print(f"header Content-Type: {contentType}")
    if contentType == "application/json":
        pprint(request.json)


#omaginai !!!
app.run(host='localhost', port=8080, debug=True, reloader=True)

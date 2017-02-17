import webapp2, jinja2, os, re
from google.appengine.ext import db
from models import Post, User
import hashutils
import math

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


# class for gathering various methods used by request handlers
class BlogHandler(webapp2.RequestHandler):

    # Get all posts ordered by creation date (descending)
    def get_posts(self, limit, offset):
        query = Post.all().order('-created')
        return query.fetch(limit=limit, offset=offset)

    # Get all posts by user, ordered by creation date (descending)
    def get_posts_by_user(self, user, limit, offset):
        query = Post.all().filter('author', user.username).order('-created')
        return query.fetch(limit=limit, offset=offset)

    # Get a user object from the db, based on their username
    def get_user_by_name(self, username):
        user = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username)
        if user:
            return user.get()

    # Login a user specified by a User object user
    def login_user(self, user):
        user_id = user.key().id()
        self.set_secure_cookie('user_id', str(user_id))

    # Logout a user specified by a User object user
    def logout_user(self):
        self.set_secure_cookie('user_id', '')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val:
            return hashutils.check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = hashutils.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    # restrict access to certain pages (global auth_paths list) when not logged in
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

        if not self.user and self.request.path in auth_paths:
            self.redirect('/login')


# class to list all blog users
class IndexHandler(BlogHandler):
    def get(self):
        users = User.all()
        allUsers = users.count()
        t = jinja_env.get_template("index.html")
        try:
            thisUser = str(self.user.username)
        except:
            thisUser = ""
        response = t.render(users = users, allUsers = allUsers, thisUser = thisUser)
        self.response.write(response)


# class to list all blog posts
class BlogIndexHandler(BlogHandler):
    page_size = 5
    def get(self, username=""):
        # If request is for a specific page, set page number and offset accordingly
        page = self.request.get("page")
        offset = 0
        page = page and int(page)
        if page:
            offset = (int(page) - 1) * self.page_size
        else:
            page = 1
        # fetch posts for all users, or a specific user, depending on request parameters
        if username:
            user = self.get_user_by_name(username)
            posts = self.get_posts_by_user(user, self.page_size, offset)
        else:
            posts = self.get_posts(self.page_size, offset)
        # determine next/prev page numbers for navigation links
        if page > 1:
            prev_page = page - 1
        else:
            prev_page = None
        if len(posts) == self.page_size and Post.all().count() > offset+self.page_size:
            next_page = page + 1
        else:
            next_page = None
        try:
            thisUser = str(self.user.username)
        except:
            thisUser = ""
        allPosts = len(posts)
        allPg = allPosts // self.page_size + (allPosts % self.page_size > 0)
        if allPg < 1:
            allPg = 1
        # render the page
        t = jinja_env.get_template("blog.html")
        response = t.render(
                    posts=posts,
                    allPosts=allPosts,
                    allPg = allPg,
                    page=page,
                    page_size=self.page_size,
                    prev_page=prev_page,
                    next_page=next_page,
                    thisUser = thisUser)
        self.response.out.write(response)

class NewPostHandler(BlogHandler):

    # Render the new post form with or without an error, based on parameters
    def render_form(self, title="", body="", error=""):
        try:
            thisUser = str(self.user.username)
        except:
            thisUser = ""
        t = jinja_env.get_template("newpost.html")
        response = t.render(title=title, body=body, error=error, thisUser=thisUser)
        self.response.out.write(response)

    def get(self):
        self.render_form()

    # Create a new blog post if possible. Otherwise, return with an error message
    def post(self):
        title = self.request.get("title")
        body = self.request.get("body")
        if title and body:
            # create a new Post object and store it in the database
            post = Post(
                title=title,
                body=body,
                author=str(self.user.username))
            post.put()

            # get the id of the new post, so we can render the post's page (via the permalink)
            id = post.key().id()
            self.redirect("/blog/%s" % id)
        else:
            error = "<strong>Error:</strong> We can't create a post without a post title <u>and</u> post content. Please try again."
            self.render_form(title, body, error)

# Render a page with post determined by the id (via the URL/permalink)
class ViewPostHandler(BlogHandler):
    def get(self, id):
        post = Post.get_by_id(int(id))
        try:
            thisUser = str(self.user.username)
        except:
            thisUser = ""
        if post:
            t = jinja_env.get_template("post.html")
            response = t.render(post=post, thisUser = thisUser)
        else:
            error = "there is no post with id %s" % id
            t = jinja_env.get_template("404.html")
            response = t.render(error=error, thisUser = thisUser)

        self.response.out.write(response)

class SignupHandler(BlogHandler):
    def validate_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        if USER_RE.match(username):
            return username
        else:
            return ""

    def validate_password(self, password):
        PWD_RE = re.compile(r"^.{3,20}$")
        if PWD_RE.match(password):
            return password
        else:
            return ""

    def validate_verify(self, password, verify):
        if password == verify:
            return verify

    def validate_email(self, email):
        # allow empty email field
        if not email:
            return ""

        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if EMAIL_RE.match(email):
            return email

    def get(self):
        try:
            thisUser = str(self.user.username)
        except:
            thisUser = ""
        t = jinja_env.get_template("signup.html")
        response = t.render(errors={}, thisUser = thisUser)
        self.response.out.write(response)

    # Validate submitted data, creating a new user if all fields are valid.
    # If data doesn't validate, render the form again with an error
    def post(self):
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")
        submitted_verify = self.request.get("verify")
        submitted_email = self.request.get("email")

        username = self.validate_username(submitted_username)
        password = self.validate_password(submitted_password)
        verify = self.validate_verify(submitted_password, submitted_verify)
        email = self.validate_email(submitted_email)

        errors = {}
        existing_user = self.get_user_by_name(username)
        has_error = False

        if existing_user:
            errors['username_error'] = "Sorry, that username already exists."
            has_error = True
        elif (username and password and verify and (email is not None) ):

            # create new user object and store it in the database
            pw_hash = hashutils.make_pw_hash(username, password)
            user = User(username=username, email=email, pw_hash=pw_hash)
            user.put()

            # login our new user
            self.login_user(user)
        else:
            has_error = True

            if not username:
                errors['username_error'] = "That's not a valid username"

            if not password:
                errors['password_error'] = "That's not a valid password"

            if not verify:
                errors['verify_error'] = "Passwords don't match"

            if email is None:
                errors['email_error'] = "That's not a valid email"

        if has_error:
            try:
                thisUser = str(self.user.username)
            except:
                thisUser = ""
            t = jinja_env.get_template("signup.html")
            response = t.render(username=username, email=email, errors=errors, thisUser = thisUser)
            self.response.out.write(response)
        else:
            self.redirect('/blog/newpost')

class LoginHandler(BlogHandler):

    # Render the login form with or without an error, based on parameters
    def render_login_form(self, error=""):
        try:
            thisUser = str(self.user.username)
        except:
            thisUser = ""
        t = jinja_env.get_template("login.html")
        response = t.render(error=error, thisUser = thisUser)
        self.response.out.write(response)

    def get(self):
        self.render_login_form()

    def post(self):
        submitted_username = self.request.get("username")
        submitted_password = self.request.get("password")

        # get the user from the database
        user = self.get_user_by_name(submitted_username)

        if not user:
            self.render_login_form(error="Invalid username")
        elif hashutils.valid_pw(submitted_username, submitted_password, user.pw_hash):
            self.login_user(user)
            self.redirect('/blog/newpost')
        else:
            self.render_login_form(error="Invalid password")

class LogoutHandler(BlogHandler):
    def get(self):
        self.logout_user()
        self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/blog', BlogIndexHandler),
    ('/blog/newpost', NewPostHandler),
    webapp2.Route('/blog/<id:\d+>', ViewPostHandler),
    webapp2.Route('/blog/<username:[a-zA-Z0-9_-]{3,20}>', BlogIndexHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler)
], debug=True)

# A list of paths that a user must be logged in to access
auth_paths = [
    '/blog/newpost'
]

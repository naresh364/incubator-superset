from flask import redirect, g, flash, request, Response
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
import jwt

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    @expose('/iframe/', methods=['GET', 'POST'])
    def iframe(self):

        from superset import app
        jwt_secret = app.config['IFRAME_JWT_SECRET']
        token = request.args.get('token')
        if not token:
           return Response(response='{"msg":"Invalid token"}', status=403, mimetype="application/json")
        try:
            jwt_payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        except jwt.exceptions.ExpiredSignatureError as err:
            return Response(response='{"msg":"Expired token"}', status=403, mimetype="application/json")
        username = jwt_payload.get("username")
        redirect_url = jwt_payload.get('redirect_url')

        if not redirect_url:
            return Response(response='{"msg":"Invalid token"}', status=403, mimetype="application/json")

        if username is not None:
            user = self.appbuilder.sm.find_user(username=username)
            if not user:
                return Response(response='{"msg":"Invalid token"}', status=403, mimetype="application/json")

            login_user(user, remember=False)
            return redirect(redirect_url)
        elif g.user is not None and g.user.is_authenticated:
            return redirect(redirect_url)
        else:
            #flash('Unable to auto login', 'warning')
            return Response(response='{"msg":"Invalid token"}', status=403, mimetype="application/json")

class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
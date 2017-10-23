import Vapor
import AuthProvider
import Sessions
import HTTP


final class Routes: RouteCollection {
    let view: ViewRenderer
    
    // route builder for protected routes
    let authRouteBuilder : RouteBuilder
    // route builder for login routes
    let loginRouteBuilder : RouteBuilder
    // 1. we need a reference to our droplet to create the routes
    init(_ view: ViewRenderer, _ drop: Droplet) {
        self.view = view  // keep as default
        
        // create the password middleware with our User
        let passwordMiddleware = PasswordAuthenticationMiddleware(User.self)
        // create the memory storage for our sessions
        let memory = MemorySessions()
        // create the persist midddleware with our User
        let persistMiddleware = PersistMiddleware(User.self)
        // create the sessions middleware with our memory
        let sessionsMiddleware = SessionsMiddleware(memory)
        
        // 2. with everything instantiated, create the two auth routes
        /// first route is for password protected routes
        self.authRouteBuilder = drop.grouped([sessionsMiddleware, persistMiddleware, passwordMiddleware])
        /// second route is to login -- this route needs sessions and persist middleware
        /// for generating the vapor access token used in future requests for logged-in users
        self.loginRouteBuilder = drop.grouped([sessionsMiddleware, persistMiddleware])
        
    }

    func build(_ builder: RouteBuilder) throws {
        /// GET /
        builder.get { req in
            return try self.view.make("welcome")
        }

        // GET|POST /register
        builder.get("register") { req in
            return try self.view.make("register")
        }
        
        // 1. modify this controller to be built by the authRouteBuilder to protect all its routes
        /// GET /hello/...
        authRouteBuilder.resource("hello", HelloController(view))
        
        // 2. create the login route
        builder.get("login") { req in
            return try self.view.make("login")
        }
        
        // 3. implement the login logic using the loginRouteBuilder so our session is persisted
        loginRouteBuilder.post("login") { req in
            guard let email = req.formURLEncoded?["email"]?.string,
                let password = req.formURLEncoded?["password"]?.string else {
                    return "Bad credentials"
            }
            
            // create a Password object with email and password
            let credentials = Password(username: email, password: password)
            
            // User.authenticate queries the user by username and password to inform middleware that user is authenticated.
            // The middleware creates a session token, ties it to the user and sends it in a cookie to the client. The
            // requests done with this request token automatically are authenticated with this user.
            let user = try User.authenticate(credentials)
            req.auth.authenticate(user)
            
            // redirect to the protected /hello route
            return Response(redirect: "hello")
        }
        
        builder.post("register") { req in
            if  let name = req.formURLEncoded?["name"]?.string,
                !name.isEmpty,
                let email = req.formURLEncoded?["email"]?.string,
                !email.isEmpty,
                let password = req.formURLEncoded?["password"]?.string,
                !password.isEmpty{
                    let user = User(name: name, email: email, password: password)
                    try user.save()
                    return "success"
                }
            return "failed"
        }
        
        // response to requests to /info domain
        // with a description of the request
        builder.get("info") { req in
            return req.description
        }
    }
}

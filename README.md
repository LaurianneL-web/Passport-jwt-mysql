# **Passport-jwt-mysql**

A simple nodejs application, which uses passportjs jwt.

## Getting Started

- Git clone https://github.com/qdanneville/passport-jwt-mysql`
- `npm install`
- `npm run start-dev`

### **Description**

#### 	**Package.json**

This file summarizes all our dependencies, which is in node_modules.
As well as the configuration of the project.

#### 	**Server.js**

Server creation and module configuration.

#### **db.js**

This file allow connection and request to database. To connect we use variables import from main.js file.

#### **Passport.js**

Passeport is an intermediate of request which will verify the authentification with a token by posted datas.

#### 	Main.js

BDD connection.

#### **Route.js**

Routes is the file which we define our routes. 

#### **Crypt.js**

Crypt.js is the file which allow you to hash a password or compare 2 passwords.

```js
crypt.createHash = function (data, successCallback, failureCallback) {
    bcrypt.genSalt(10, function (err, salt) {
        if (err) {
            failureCallback(err);
            return;
        }
        bcrypt.hash(data, salt, null, function (err, hash) {
            if (err) {
                failureCallback(err);
                return;
            }
            successCallback(hash);
        });
    });
};
```

createHash function allow us to hash a password with a secret (a unique string) from data password.

```js
crypt.compareHash = function (data, encrypted, successCallback, failureCallback) {
    bcrypt.compare(data, encrypted, function (err, isMatch) {
        if (err) {
            failureCallback(err);
            return;
        }
        successCallback(err, isMatch);
    });
};
```

compareHash function is used to compare 2 passwords( one from data request and the other from database).

#### **User.controller.js**

Controller is the conductor of the association between routes and function.

```js
function register(userParam, callback) {
    if (!userParam.email || !userParam.password) {
        return callback({ success: false, message: 'Please enter email and password.' });
    } else {
        var newUser = {
            email: userParam.email,
            password: userParam.password
        };

        // Attempt to save the user
        db.createUser(newUser, function (res) {
            return callback({ success: true, message: 'Successfully created new user.' });
        }, function (err) {
            return callback({ success: false, message: 'That email address already exists.' });
        });
    }
}
```

Register function allow us to to verify if email and password datas is true and to create a new user from data inside db?js using createUser function.

```js
function authenticate({ email, password }, callback) {
    db.findUser({
        email: email
    }, function (res) {
        var user = {
            user_id: res.user_id,
            user_email: res.user_email,
            is_active: res.is_active,
            user_type: res.user_type
        };

        // Check if password matches
        crypt.compareHash(password, res.password, function (err, isMatch) {
            if (isMatch && !err) {
                // Create token if the password matched and no error was thrown
                var token = jwt.sign(user, config.secret, {
                    expiresIn: 10080 // in seconds
                });
                return callback({ success: true, token: token });
            } else {
                return callback({
                    success: false,
                    message: 'Authentication failed. Passwords did not match.'
                });
            }
        });
    }, function (err) {
        return callback({ success: false, message: 'Authentication failed. User not found.' });
    });
}
```

Authenticticate function allow us to to verify if email is already used inside database and if it's true, it get user datas from database and compare password from request and password find inside database from email.

#### **User.service.js**

Service allow us to serve datas between database and the navigator.

```js
function register(req, res) {
    userService
        .register(req.body, result => {
            result.success ? res.status(201).json(result) : res.status(401).json(result);
        })
}
```

Register function use db.js required inside variable userService witch allow us to acces function register.

```js
function authenticate(req, res) {
    userService
        .authenticate(req.body, result => {
            result.success ? res.status(201).json(result) : res.status(401).json(result);
        })
}
```

Authenticate function use db.js required inside variable userService witch allow us to acces function authenticate.

### **Authors**

Vamshi Adi



### **Contributors**

Julia BARGOIN

Laurianne LEBRETON
const jwt = require("jsonwebtoken")
const { JWT_USER_PASSWORD } = require("../config")



function userMiddleware(req, res, next) {
    const token = req.headers.token
    const decodedData = jwt.verify(token, JWT_USER_PASSWORD)
    if (decodedData) {
        req.userId = decodedData._id,
            next();
    }
}


module.exports = {
    userMiddleware: userMiddleware
}



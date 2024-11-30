const express = require("express")
// const Router = express.Router
const bcrypt = require("bcrypt")
const { z } = require("zod")
const { userModel, purchaseModel } = require("../db")
const jwt = require("jsonwebtoken")
const { JWT_USER_PASSWORD } = require("../config");
const { userMiddleware } = require("../middleware/user")
const { Router } = require("express");

const userRouter = Router();
userRouter.use(express.json());


userRouter.post("/signup", async function (req, res) {
    const requiredBody = z.object({
        email: z.string()
            .min(4)
            .max(30, { message: "Password should not contain more then 30 letter" }),
        password: z.string()
            .regex(/[A-Z]/, { message: "Password must be contain at least one Capital letter" })
            .regex(/[a-z]/, { message: "Password must be contain at least one small letter" })
            .regex(/[0-9]/, { message: "Password must be contain at least one number" })
            .regex(/[@#$%^&*(){}<>?:"]/, { message: "Password must be contain at least one special character" })
    })

    const passDataWithSuccess = requiredBody.safeParse(req.body);

    if (!passDataWithSuccess.success) {
        res.json({
            message: "incorect format",
            error: passDataWithSuccess.error
        })
        return
    }


    const { email, password, firstName, lastName } = req.body;

    const hashedPassword = await bcrypt.hash(password, 5);


    try {
        await userModel.create({
            email: email,
            password: hashedPassword,
            firstName: firstName,
            lastName: lastName

        })
    } catch (e) {
        res.json({
            message: "something Wrong try again"
        })
    }

    res.json({
        message: "you are signup successfully "
    })


})



userRouter.post("/signin", async function (req, res) {

    const requiredBody = z.object({
        email: z.string()
            .min(4)
            .max(30, { message: "Passwgord must be contain at maximum 30 letter" }),
        password: z.string()
            .regex(/[A-Z]/, { message: "Password must be contain at least one Capital letter" })
            .regex(/[a-z]/, { message: "Password must be contain at least one small letter" })
            .regex(/[0-9]/, { message: "Password must be contain at least one number" })
            .regex(/[@#$%^&*(){}<>?:"]/, { message: "Password must be contain at least one special character" })
    })

    const passDataWithSuccess = requiredBody.safeParse(req.body);

    if (!passDataWithSuccess.success) {
        res.json({
            message: "incorect format",
            error: passDataWithSuccess.error
        })
        return
    }


    const { email, password, firstName, lastName } = req.body;

    const response = await userModel.findOne({
        email: email
    })
    if (!response) {
        res.json({
            message: " email dose not exist in database"
        })
        return
    }


    const passwordMatch = bcrypt.compare(password, response.password)

    if (passwordMatch) {
        const token = jwt.sign({
            id: response._id
        }, JWT_USER_PASSWORD);

        // add cookie logic

        res.json({
            token
        })
    } else {
        res.status(403).json({
            message: "Incorrect Cread"
        })
    }



})
userRouter.get("/purchases", userMiddleware, async function (req, res) {
    const userId = req.userId;

    const purchases = await purchaseModel.find({
        userId
    })

    res.json({
        purchases,

    })
})

module.exports = {
    userRouter: userRouter
}
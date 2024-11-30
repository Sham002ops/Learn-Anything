const { Router } = require("express")
const { adminModel, courseModel } = require("../db")
const { z } = require("zod")
const bcrypt = require("bcrypt")
const adminRouter = Router();
const jwt = require("jsonwebtoken")
const { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middleware/admin")


adminRouter.post("/signup", async function (req, res) {
    const requiredBody = z.object({
        firstName: z.string(),
        lastName: z.string(),

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

    const hashedPassword = await bcrypt.hash(password, 5);



    await adminModel.create({
        email: email,
        password: hashedPassword,
        firstName: firstName,
        lastName: lastName

    })

    res.json({
        message: "you are signup successfully "
    })


})
adminRouter.post("/signin", async function (req, res) {
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

    const response = await adminModel.findOne({
        email: email
    })

    // if (!password || !response.Password) {
    //     return res.status(400).json({
    //         message: "Password or hashed password missing"
    //     });
    // }
    if (!response) {
        res.json({
            message: " email dose not exist in database"
        })
        return
    }




    const passwordMatch = await bcrypt.compare(password, response.password)

    if (passwordMatch) {
        const token = jwt.sign({
            id: response._id
        }, JWT_ADMIN_PASSWORD);

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

adminRouter.post("/course", adminMiddleware, async function (req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price } = req.body;

    const course = await courseModel.create({
        title: title,
        description: description,
        imageUrl: imageUrl,
        price: price,
        creatorId: adminId
    })
    res.json({
        message: "Course created",
        courseId: course._id
    })
})
adminRouter.put("/course", adminMiddleware, async function (req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price, courseId } = req.body;

    const course = await courseModel.updateOne({
        _id: courseId,
        creatorId: adminId
    },
        {
            title: title,
            description: description,
            imageUrl: imageUrl,
            price: price,
        })
    res.json({
        message: "Course updated",
        courseId: course._id
    })
})
adminRouter.get("/course/bulk", adminMiddleware, async function (req, res) {
    const adminId = req.userId;

    const courses = await courseModel.find({
        creatorId: adminId
    });
    res.json({
        message: "Course preview",
        courses
    })
})
module.exports = {
    adminRouter: adminRouter
}
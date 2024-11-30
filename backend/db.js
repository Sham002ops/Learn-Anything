const mongoose = require("mongoose")

const Schema = mongoose.Schema
const ObjectId = mongoose.Types.ObjectId;


const userSchema = new Schema({
    userId: ObjectId,
    email: { type: String, unique: true },
    password: String,
    firstName: String,
    lastName: String

})
const adminSchema = new Schema({
    adminId: ObjectId,
    email: { type: String, unique: true },
    password: String,
    firstName: String,
    lastName: String

})

const courseSchema = new Schema({

    title: String,
    description: String,
    price: Number,
    imageUrl: String,
    CreatorId: ObjectId
})

const purchaseSchema = new Schema({
    purchaseId: ObjectId,
    courseId: ObjectId,
    userId: ObjectId,
})


const userModel = mongoose.model("user", userSchema);
const adminModel = mongoose.model("admin", adminSchema);
const courseModel = mongoose.model("course", courseSchema);
const purchaseModel = mongoose.model("purchase", purchaseSchema);

module.exports = {
    userModel,
    adminModel,
    courseModel,
    purchaseModel
}
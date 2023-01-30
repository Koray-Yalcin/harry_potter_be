import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";
import userRouter from './Routers/userRouter.js';

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());
app.use("/users", userRouter);

app.listen(5000, () => {
  mongoose
    .connect(process.env.URL)
    .then(() => console.log("connected to db"))
    .catch((error) => console.log(error));
});
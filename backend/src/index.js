import express, { urlencoded } from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
import cookieParser from "cookie-parser";
dotenv.config();


const PORT=process.env.PORT||8080

const app=express();
app.use(express.json());
app.use(cookieParser())
app.use('/api/v1/auth',authRoutes)
app.listen(PORT,()=>{
    console.log(`server is listening at port ${PORT}`)
})

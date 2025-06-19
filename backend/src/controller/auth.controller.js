import { db } from "../libs/db.js";

// import { UserRole } from "../generated/prisma/index.js";
// import { PrismaClient, UserRole } from "@prisma/client";
import { PrismaClient, UserRole } from "../generated/prisma/index.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";


export const register=async(req,res)=>{
    const{name,email,password,role}=req.body
    if(!name||!email||!password){
        return res.status(401).json({
            success:false,
            message:"Credentials Missing"
        })
    }
    try {
        const existingUser=await db.User.findUnique({
            where:{
                email
            }
        })
        if(existingUser){
            return res.status(401).json({
                success:false,
                message:"User already exist"
            })
        }
        const hashedPassword=  await bcrypt.hash(password,10);

            const newUser=await db.user.create({
                data:{
                    name,
                    email,
                    password:hashedPassword,
                    role:UserRole.USER
                }
            })
        const jwttoken=jwt.sign({id:newUser.id},
            process.env.JWT_SECRET,
            {expiresIn:"1d"}
        )
          res.cookie("jwt" , jwttoken , {
            httpOnly:true,
            sameSite:"strict",
            secure:process.env.NODE_ENV !== "development",
            maxAge:1000 * 60 * 60 * 24 * 7 
          })
          res.status(201).json({
            success:true,
            message:"User Registered succesfully ",
            user:{
                id:newUser.id,
                email:newUser.email,
                name:newUser.name,
                role:newUser.role,
                image:newUser.image
            }
          })


        
    } catch (error) {
        console.error('error creating user',error)
        res.status(500).json({
            error:"error creating error"
        })
        
    }
}
export const login=async(req,res)=>{
    const{email,password}=req.body;
    // console.log(email,password)
    if(!email||!password){
        return res.status(401).json({
            success:false,
            message:"Missing Credentials"
        })
    }
    try {
        const loggedinUser=await db.user.findUnique({
            where:{
                email
            }
        })
        if(!loggedinUser){
            return res.status(401).json({
                success:false,
                message:"user not registered"
            })

        }
        const isMatched=await bcrypt.compare(password,loggedinUser.password)
        // console.log(isMatched)
        if(!isMatched){
            return res.status(401).json({
                success:false,
                message:"Invalid email or password"
            })

        }
        const jwttoken=jwt.sign({id:loggedinUser.id},process.env.JWT_SECRET,{expiresIn:"1d"})
        // console.log(jwttoken)

        res.cookie("jwt",jwttoken,{
            httpOnly:true,
            sameSite:"Strict",
            secure:process.env.NODE_ENV !== "development",
            maxAge:1000 * 60 * 60 * 24 * 7 
        })
        res.status(201).json({
            success:true,
            message:"user Logged In",
            user:{
                id:loggedinUser.id,
                name:loggedinUser.name,
                email:loggedinUser.email,
                image:loggedinUser.image,
                role:loggedinUser.role
            }
        })
        
    } catch (error) {
        console.error('Error logginIn User',error)
        res.status(500).json({
            message:error,
            success:false
        })

        
    }
}
export const logout=async(req,res)=>{
    try {
        res.clearCookie("jwt",{
            httpOnly:true,
            sameSite:"strict",
            secure:process.env.NODE_ENV !== "development"

        })
        res.status(200).json({
            success:true,
            message:"User LoggedOut Successfully"

        })
    } catch (error) {
        console.error("error logging out user",error)
        res.status(500).json({
            success:false,
            message:"internal server error"
        })

        
    }
}
export const check=async(req,res)=>{
    
    try {
        res.status(200).json({
            success:true,
            message:"user authenticated succesfully",
            user:req.user

        })
        
    } catch (error) {
        console.error("error checking user,error")
        res.status(500).json({
            success:false,
            message:"internal server error"
        })
        
    }
}


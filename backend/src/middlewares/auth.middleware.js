import db from "../libs/db.js"
import  jwt from "jsonwebtoken";

export const authMiddleware=async(req,res,next)=>{
    try {
        const token=res.cookies.jwt
        if(!token){
            return res.status(401).message({
                success:false,
                message:"token not found"
            })

        }
        let decoded;
        try {
            decoded= await jwt.verify(token,process.env.JWT_SECRET)
            console.log(decoded)
        } catch (error) {
            res.status(401).json({
                message:"unauthorized-invalid token"
            })
            
        }
        const user=await db.user.findUnique({
            where:{
                id:decoded.id
            },
            select:{
                id:true,
                name:true,
                email:true,
                image:true,
                role:true,
            }
        })
        if(!user){
            return res.status(401).json({
                success:false,
                message:"user not found"
            })
        }
        req.user=user;
        next();
        
    } catch (error) {
        console.error('error creating middleware',error)
        res.status(500).json({
            success:false,
            message:"Internal Server error"
        })
    }
    
}

export const checkAdmin=async(req,res)=>{
    const userId=req.user.id;
    if(!userId){
        return res.status(401).json({
            success:false,
            message:"User id not found"
        })
    }
    try {
        const user=await db.user.findUnique({
            where:{
                id:userId
            },
            select:{
             role:true
            }
        })
        if(!user || user.role!=="ADMIN"){
            return req.status(401).json({
                success:false,
                message:"Unauthorized access-ADMIN ONLY"
            })
        }
        next();
    } catch (error) {
        console.log(error,"error checking role")
        return res.status(500).json({
            message:"Internal Server error"
        })
        
    }
}
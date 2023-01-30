import express from "express";
import bcrypt from 'bcryptjs'
import User from '../models/userModel.js';
import dotenv from 'dotenv';
import auth from "../Middleware/auth.js";
import jwt from "jsonwebtoken";
import tokenModel from '../Models/tokenModel.js';

const router = express.Router();
dotenv.config();

router.post("/register", async (req, res)=>{
    try {
        const { fullname, username, password, confirmPassword, email } = req.body;
        const userExists = await User.findOne({ email });

        if(userExists)
            return res.status(400).json({ message: 'User already exists.'})

        if (password !== confirmPassword)
            return res.status(400).json({ message: 'Passwords not match' })

        const hashedPassword = await bcrypt.hash(password, 10)

        const user = await User.create({
            fullname,
            username,
            email,
            password: hashedPassword
        });

        const accessToken = jwt.sign(
            { email: user.email, id: user._id },
            'ACCESS_TOKEN_SECRET',
            {
              expiresIn: '3m',
            }
          )
      
          const refreshToken = jwt.sign(
            { email: user.email, id: user._id },
            'REFRESH_TOKEN_SECRET'
          )
      
          await tokenModel.create({
            userId: user._id,
            refreshToken: refreshToken,
          })
      
          res.cookie('token', refreshToken, {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
          })
          res.status(200).json({ user, accessToken })
    } catch (error) {
        console.log(error)
        return res.json({message: error.message})
    }
})

router.post("/login", async (req,res)=>{
    try {
        const {email, password} = req.body;
        const user = await User.findOne({email})
        if(!user)
            return res.status(400).json({message: "user does not exist"})
        
        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if(!isPasswordCorrect)
            return res.status(400).json({message: "Wrong Password"})

        const accessToken = jwt.sign(
            { email: user.email, id: user._id },
            'ACCESS_TOKEN_SECRET',
            { expiresIn: '3m' }
            )
        
            const refreshToken = jwt.sign(
            { email: user.email, id: user._id },
            'REFRESH_TOKEN_SECRET'
            )
        
            await tokenModel.findOneAndUpdate(
            { userId: user._id },
            {
                refreshToken: refreshToken,
            },
            { new: true }
            )
        
            res.cookie('token', refreshToken, {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            })
            res.status(200).json({ user, accessToken })
    } catch (error) {
        return res.status(400).json({ message: error.message })
    }
})

router.get('/logout/:id', async (req, res) => {
    try {
      const { id } = req.params
  
      res.clearCookie('token')
      await tokenModel.findOneAndUpdate(
        {
          userId: id,
        },
        { refreshToken: null },
        { new: true }
      )
  
      res.status(200).json({ message: 'Logout Successfull' })
    } catch (error) {
      res.status(500).json(error)
    }
  })

export default router;
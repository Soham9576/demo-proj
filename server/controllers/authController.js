import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";


export const register = async(req, res) => {
    const { name, email, password } = req.body;
    if(!name || !email || !password) {
        return res.json({success: false, message: "Missing Details "});
    }

try {
    const existingUser = await userModel.findOne({email});
    if(existingUser) {
        return res.json({success: false, message: "User already exists"});
    }
    const HashedPassword = await bcrypt.hash(password, 10);
    const user=new userModel({name, email, password: HashedPassword});
    await user.save();

    const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: "7d"});
    res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV=== "production" ,
        sameSite: process.env.NODE_ENV=== "production" ? "none" : "strict",
        maxAge: 7*24*60*60*1000,
    });
    //sending welcome email to user
    const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: email,
        subject: "Welcome to Our App",
        text: `Hello,\n\nWelcome to our application! Your account has been created  with email id: ${email}. We're excited to have you on board.\n\nBest regards,\nThe Team`
    };

    await transporter.sendMail(mailOptions);

    return res.json({success: true});

    }catch(error) {
    return res.json({success: false, message: error.message});
    }
}


export const login = async (req, res) => {
    const { email, password } = req.body;
    if(!email || !password) {
        return res.json({success: false, message: "Missing Details "});
    }
    try {
        const existingUser = await userModel.findOne({email});
        if(!existingUser) {
            return res.json({success: false, message: "Invalid Email" });
        }
        const isMatch = await bcrypt.compare(password, existingUser.password);
        if(!isMatch) {
            return res.json({success: false, message: "Invalid password" });
        }
    
        const token = jwt.sign({id: existingUser._id}, process.env.JWT_SECRET, {expiresIn: "7d"});
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV=== "production" ,
            sameSite: process.env.NODE_ENV=== "production" ? "none" : "strict",
            maxAge: 7*24*60*60*1000,
        });
        return res.json({success: true});
    
    }catch(error) {
        return res.json({success: false, message: error.message});
    }
}

export const logout = (req, res) => {
    try{
        res.clearCookie("token", {
            httpOnly: true,
            secure: process.env.NODE_ENV=== "production" ,
            sameSite: process.env.NODE_ENV=== "production" ? "none" : "strict",
        });
        return res.json({success: true, message: "Logged out successfully"});
    } catch(error) {
        return res.json({success: false, message: error.message});
    }
}

export const sendVerifyOtp = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await userModel.findById(userId);  

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.isAccountVerified) {
      return res.json({ success: false, message: "Account already verified" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.verifyOtp = otp;
    user.verifyOtpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `Hello,\n\nYour OTP for account verification is ${otp}. It is valid for 10 minutes.\n\nBest regards,\nThe Team`
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "Verification OTP sent to your email" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//verofy email using otp
export const verifyEmail = async (req, res) => {
  const { otp } = req.body;   // only OTP should come from frontend
  const userId = req.user.id; // userId comes from JWT in middleware

  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing Details" });
  }

  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }
    if (user.verifyOtpExpiry < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }

    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpiry = 0;
    await user.save();

    return res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const isAuthenticated = async (req, res) => {
    try {
        return res.json({success: true});
    } catch(error) {
        return res.json({success: false, message: error.message});
    }
}

//send reset password otp to email
export const sendResetotp = async (req, res) => {
    const { email } = req.body;
    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }
    try {
      const user = await userModel.findOne({ email });
      if (!user) {  
        return res.json({ success: false, message: "User not found" });
      }
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.resetOtp = otp;
    user.resetOtpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      text: `Hello,\n\nYour OTP for password reset is ${otp}.Use this OTP for resetting your password. It is valid for 10 minutes.\n\nBest regards,\nThe Team`
    };

    await transporter.sendMail(mailOptions);
    return res.json({ success: true, message: "Password reset OTP sent to your email" });
      
    }
    catch (error) {
      return res.json({ success: false, message: error.message });
    }
}
//reset password using otp
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: "Missing Details" });
    }
    
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
        return res.json({ success: false, message: "User not found" });
        }
        if (user.resetOtp === "" || user.resetOtp !== otp) {
        return res.json({ success: false, message: "Invalid OTP" });
        }
        if (user.resetOtpExpiry < Date.now()) {
        return res.json({ success: false, message: "OTP Expired" });
        }
    
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpiry = 0;
        await user.save();
    
        return res.json({ success: true, message: "Password reset successfully" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
} 

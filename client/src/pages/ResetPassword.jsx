import React, { useContext, useState } from 'react'
import { assets } from '../assets/assets'
import { useNavigate } from 'react-router-dom'
import { AppContext } from '../context/AppContext'
import axios from 'axios'
import { toast } from 'react-toastify'

const ResetPassword = () => {


const {backendUrl}=useContext(AppContext)
axios.defaults.withCredentials=true


const navigate=useNavigate()
const [email,setEmail]=useState('')
const [newPassword,setnewPassword]=useState('')
const [isEmailSent,setisEmailSent]=useState('')
const [otp,setotp]=useState(0)
const [isotpSubmitted,setisotpSubmitted]=useState(false)

const inputRefs=React.useRef([])
    const handleInput=(e,index)=>{
      if(e.target.value.length>0 && index < inputRefs.current.length - 1){
          inputRefs.current[index+1].focus();
      }
    }
    const handleKeyDown=(e,index)=>{
      if(e.key==='Backspace' && e.target.value==='' && index>0){
        inputRefs.current[index-1].focus();
      }
    }

    const onSubmitEmail=async(e)=>{
      e.preventDefault();
      try{
        const {data}=await axios.post(backendUrl + '/api/auth/send-reset-otp',{email})
        data.success? toast.success(data.message) : toast.error(data.message)
        data.success && setisEmailSent(true)

      }
      catch{
        toast.error(error.message)
      }
    }

    const onSubmitotp=async(e)=>{
      e.preventDefault();
      const otpArray=inputRefs.current.map(e=>e.value)
      setotp(otpArray.join(''))
      setisotpSubmitted(true)
      
    }
    const onSubmitnewpassword=async(e)=>{
      e.preventDefault();
      try{
        const {data}=await axios.post(backendUrl + '/api/auth/reset-password',{email,otp,newPassword})
        data.success? toast.success(data.message) : toast.error(data.message)
        data.success && navigate('/login')

      }
      catch{
        toast.error(error.message)
      }
    }


  return (
    <div className='flex items-center justify-center min-h-screen px-6 sm:px-0 bg-gradient-to-br from-blue-200 to-purple-400'>
    <img onClick={()=>navigate('/')} src={assets.logo} alt="" className='absolute left-5 sm:left-20 top-5 w-28 sm:w-32 cursor-pointer' />

{!isEmailSent &&   
  <form onSubmit={onSubmitEmail} className='bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm'>
      <h1 className='text-white text-2xl font-semibold text-center mb-4'>Reset Password</h1>
        <p className='text-center mb-6 text-indigo-300'>Enter your Registered Email address</p>
        <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'>
          <img src={assets.mail_icon} alt="" className='w-3 h-3'/>
          <input type="email" placeholder='Email Id'
          className='bg-transparent outline-none text-white'
          value={email} onChange={e=>setEmail(e.target.value)}required/>
        </div>
        <button className='w-full py-2.5 bg-indigo-600 text-white rounded-full mt-3'>Submit</button>

    </form>}

{!isotpSubmitted && isEmailSent && 
<form onSubmit={onSubmitotp} className='bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm'>
        <h1 className='text-white text-2xl font-semibold text-center mb-4'>Reset Password OTP</h1>
        <p className='text-center mb-6 text-indigo-300'>Enter the 6-digit code sent to your email id</p>
        <div className='flex justify-between mb-8'>
          {Array(6).fill(0).map((_,index)=>
          (<input type='text' maxLength='1' key={index} required
          className='w-12 h-12 bg-[#333A5C] text-white text-center text-xl rounded-md'
          ref={e=> inputRefs.current[index]= e}
          onInput={(e)=>handleInput(e,index)}
          onKeyDown={(e)=>handleKeyDown(e,index)}
          />))}
        </div>
        <button className='w-full py-3 bg-indigo-600 text-white rounded-full'>Sumbit</button>
        </form> }


{isotpSubmitted && isEmailSent &&    
<form onSubmit={onSubmitnewpassword} className='bg-slate-900 p-10 rounded-lg shadow-lg w-full sm:w-96 text-indigo-300 text-sm'>
      <h1 className='text-white text-2xl font-semibold text-center mb-4'>New Password</h1>
        <p className='text-center mb-6 text-indigo-300'>Enter the new password below</p>
        <div className='mb-4 flex items-center gap-3 w-full px-5 py-2.5 rounded-full bg-[#333A5C]'>
          <img src={assets.lock_icon} alt="" className='w-3 h-3'/>
          <input type="password" placeholder='Password'
          className='bg-transparent outline-none text-white'
          value={newPassword} onChange={e=>setnewPassword(e.target.value)}required/>
        </div>
        <button className='w-full py-2.5 bg-indigo-600 text-white rounded-full mt-3'>Submit</button>

    </form>}



    </div>
  )
}

export default ResetPassword
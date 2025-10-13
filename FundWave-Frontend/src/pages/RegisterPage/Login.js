import React, { useEffect, useState } from 'react'
import {FiMail} from "react-icons/fi"
import {RiLockPasswordLine} from "react-icons/ri"
import "../RegisterPage/RegisterPage.css"
import { Link, useNavigate } from 'react-router-dom'
import axios from 'axios';
import { useUser } from '../../context/UserContext';
import api from '../../util/api'
import './login.css'
const Login = () => {
    // Set the item in localStorage
const setLocalStorageItem = (key, value) => {
    return new Promise((resolve, reject) => {
      try {
        localStorage.setItem(key, JSON.stringify(value));
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  };
  
  // Get the item from localStorage
  const getLocalStorageItem = (key) => {
    return new Promise((resolve, reject) => {
      try {
        const item = localStorage.getItem(key);
        resolve(item ? JSON.parse(item) : null);
      } catch (error) {
        reject(error);
      }
    });
  };
  
  async function exampleUsage(userdata) {
    try {
      // Set the item
      await setLocalStorageItem('userData',userdata);
      console.log('Item set successfully.');
  
      // Get the item
      const userData = await getLocalStorageItem('userData');
      console.log('Retrieved item:', userData);
    } catch (error) {
      console.error('Error:', error);
    }
  }
    const navigate =useNavigate()
    const [error,setError] =useState({})
    const [submit,setSubmit] =useState(false)
    const { setUserData } = useUser();

    const [data,setData] =useState({
        username:"",
        password:"",
    })

    const handleChange=(e)=>{
        const newObj={...data,[e.target.name]:e.target.value}
        setData(newObj)
    }
 

    const handleSignUp = async (e) => {
        e.preventDefault();
        setError(validationLogin(data));
        setSubmit(true);
        //why u dindt work

        try {
          const response = await axios.post(`${api.url}:8000/login`, data);
          if (response.status === 200) {
                console.log('login successful!');
               // console.log(response.data.user);      
                setUserData(response.data.user);
               // localStorage.setItem('userData', JSON.stringify(response.data.user));
               exampleUsage(response.data.user);
               
                //const userData = JSON.stringify(response.data.user);
                //navigate(`/home?userData=${userData}`);
                navigate(`/home`);
            }else{
                console.log("guru");
            }
        } catch (error) {
            console.error('Failed to login:', error.message);
        }
    };
   function validationLogin(data){
        const error ={};
        // const emailPattern= /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$/;
        const passwordPattern= /^[a-zA-Z0-9!@#\$%\^\&*_=+-]{1,12}$/g;
        // if(data.email === ""){
        //     error.email ="* Email is Required"
        // }
        // else if(!emailPattern.test(data.email)){
        //     error.email="* Email did not match"
        // }
        if(data.password === ""){
            error.password = "* Password is Required"
        }
        else if(!passwordPattern.test(data.password)){
            error.password="* Password not valid"
        }
        return error
   }

  return (
    <div className="container_log">
        <div className="container-form">
            <form onSubmit={handleSignUp}>
            <h1>Login to <span class="highlight">Nos</span>talgia</h1>
                <p>Please sign in to continue.</p>
                <div className="inputBox">
                    <FiMail className='mail'/>
                    <input type="text" 
                            name="username" 
                            id="username" 
                            onChange={handleChange}
                            placeholder='Username'/> 
                </div>
                {error.username && <span style={{color:"red",display:"block",marginTop:"5px"}}>{error.username}</span>}

                <div className="inputBox">
                    <RiLockPasswordLine className='password'/>
                    <input type="password" 
                            name="password" 
                            id="password" 
                            onChange={handleChange}
                            placeholder='Password'/>
                </div>
                {error.password && <span style={{color:"red",display:"block",marginTop:"5px"}}>{error.password}</span>}
               

                <div className='divBtn'>
                <Link to="/forget" className="btn">
                    <small className='FG'>Forgot Password?</small>
                    </Link>
                    <button type='submit' className='loginBtn'>LOGIN</button>
                </div>
                
            </form>

            <div className='dont'>
                <p>Don't have an account? <Link to="/signup"><span>Sign up</span></Link></p>
            </div>
            {/* <div className='dont mb-2'>
               <Link to="/nhome"><span>View as none User</span></Link>
            </div> */}
        </div>
    </div>
  )
}

export default Login
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import "../RegisterPage/RegisterPage.css";
import { AiOutlineUser } from "react-icons/ai";
import { FiMail } from "react-icons/fi";
import { RiLockPasswordLine } from "react-icons/ri";
import { Link, useNavigate } from 'react-router-dom';
import validation from './Validation';
import api from '../../util/api';
import { set } from 'date-fns';
const SignUp = () => {
    const navigate = useNavigate();
    const [error, setError] = useState({});
    const [submit, setSubmit] = useState(false);
    const [divisions, setDivisions] = useState([
        "Dhaka",
        "Rajshahi",
        "Khulna",
        "Barishal",
        "Chattogram",
        "Sylhet",
        "Mymensingh"
    ]);
    const [upazilas, setUpazilas] = useState();
    const [districts, setDistricts] = useState([]);
    const findThana = (district) => {
        const res=axios.get(`${api.url}:8000/findthana`,{
            params: {
                district: district
            }
        }).then(response => {
            // Accessing the data from the response object
            console.log(response.data);
            setUpazilas(response.data);
        }).catch(error => {
            // Handling errors
            console.error('Error:', error);
        });
    }
    const findDistrict = (division) => {
        const res=axios.get(`${api.url}:8000/finddistrict`,{
            params: {
                division: division
            }
        }) .then(response => {
            // Accessing the data from the response object
            console.log(response.data);
            setDistricts(response.data);
        })
        .catch(error => {
            // Handling errors
            console.error('Error:', error);
        });

    }        
    const [data, setData] = useState({
        username: '',
        password: '',
        email: '',
        first_name: '',
        last_name: '',
        walk_type: 'alone',
        gender: '',
        phone: '',
        dob: '2022-01-01',
        address: '',
        nid: '',
        thana: '',
        division: '',
        district: '',
        confirm_password: ''
    });

    const handleChange = (e) => {
        setError({});
        const newObj = { ...data, [e.target.name]: e.target.value };
        const { name, value } = e.target;
        setData((prevData) => ({ ...prevData, [name]: value }));
        if (name === "division") {
            findDistrict(value);
        } else if (name === "district") {
            findThana(value);
        }
    };

    const isAgeLessThan50 = (dob) => {
        let currentDate = new Date();
        let birthDate = new Date(dob);
        let age = currentDate.getFullYear() - birthDate.getFullYear();
      
        // Adjust if the birthday hasn't occurred this year yet
        let monthDifference = currentDate.getMonth() - birthDate.getMonth();
        if (monthDifference < 0 || (monthDifference === 0 && currentDate.getDate() < birthDate.getDate())) {
          age--;
        }
      
        // Check if age is less than 50 years
        if (age < 50) {
          return false;
        }
      
        return true;
      };
      

      
    const handleSignUp = async (e) => {
        setError({});
        e.preventDefault();
        const emailPattern= /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$/;
        const passwordPattern= /^[a-zA-Z0-9!@#\$%\^\&*_=+-]{1,4}$/g;

        if(data.username === ""){
            setError({username: "username Shouldn't empty "});
            return;
        }

        if(data.first_name === ""){
            setError({first_name: "Name Shouldn't empty "});
            return;
        }
        else if(!emailPattern.test(data.email)){
            setError({email: "Give Correct Email"});
            return;

        }
        if(!isAgeLessThan50(data.dob)){
            setError({dob:"Age should be more than 50"});
            return;

        }
    
    
        if(data.password == ""){
            setError({password: "Password Shouldn't empty"});
            return;
        }
        if(data.password != data.confirm_password){
            setError({confirm_password: "Password doesn't match"});
             return;
        }
        // setError(validation(data));
        // if (Object.keys(validation(data)).length > 0) return;
        setSubmit(true);

        try {
            const response = await axios.post(`${api.url}:8000/sign`, data);
            if (response.status === 201) {
                console.log('Registration successful!');
                navigate("/");
            }
            if(response.status === 400){
                console.log('Registration failed!');
                console.log(response);
                setError(response.data);
            }
        } catch (error) {
            console.error('Failed to register:', error.message);
        }
    };

    const [email, setEmail] = useState('');
    const [message, setMessage] = useState('');

    const handleEmailVerification = async () => {
        try {
            const response = await axios.post('http://your-backend-api-url/send-verification-email', {
                email: email,
            });
            setMessage(response.data.message);
        } catch (error) {
            setMessage('Error sending verification email');
            console.error(error);
        }
    };
    return (
        <div className="container">
            <div className="container-form">
                <form onSubmit={handleSignUp}>
                    <h1>Create Account</h1>
                    <p>Please fill in the inputs below:</p>

                    <div className="inputBox">
                        <AiOutlineUser className='username' />
                        <input className='form-control'  type='text'
                            name="username"
                            id="username"
                            onChange={handleChange}
                            placeholder='Username'
                        />
                    </div>
                    {error.username && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.username}</span>}

                    <div className="inputBox">
                        <AiOutlineUser className='first_name' />
                        <input  className='form-control' type='text'
                            name="first_name"
                            id="first_name"
                            onChange={handleChange}
                            placeholder='First Name'
                        />
                    </div>
                    {error.first_name && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.first_name}</span>}
                    <div className="inputBox">
                        <AiOutlineUser className='last_name' />
                        <input  className='form-control' type='text'
                            name="last_name"
                            id="last_name"
                            onChange={handleChange}
                            placeholder='Last Name'
                        />
                    </div>
                    {error.last_name && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.last_name}</span>}

                    <div className="inputBox">
                        <FiMail className='mail' />
                        <input  className='form-control' type="email"
                            name="email"
                            id="email"
                            onChange={handleChange}
                            placeholder='Email'
                        />
                    </div>
                    {error.email && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.email}</span>}

                    <div className="inputBox">
                        <FiMail className='address' />
                        <input  className='form-control' type="text"
                            name="address"
                            id="address"
                            onChange={handleChange}
                            placeholder='Address'
                        />
                    </div>
                    {error.address && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.address}</span>}

                    <div className="inputBox">
                        <FiMail className='nid' />
                        <input  className='form-control' type="text"
                            name="nid"
                            id="nid"
                            onChange={handleChange}
                            placeholder='NID'
                        />
                    </div>
                    {error.nid && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.nid}</span>}

                    <div className="inputBox" >
                        <FiMail className='phone' />
                        <input className='form-control' type="text"
                            name="phone"
                            id="phone"
                            onChange={handleChange}
                            placeholder='Phone'
                        />
                    </div>
                    {error.phone && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.phone}</span>}

                    <div className="inputBox " style={{ width: "100%" }}>
                        <select className='form-control' name="division" id="division" onChange={handleChange}>
                            <option value="">Select Division</option>
                            {divisions.map((division) => (
                                <option key={division} value={division}>
                                    {division}
                                </option>
                            ))}
                        </select>
                    </div>
                    {error.division && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.division}</span>}
                    { districts && (
                        <div className="inputBox" style={{width:"100%"}}>
                            <select  className='form-control'  name="district" id="district" onChange={handleChange}>
                                <option value="">Select District</option>
                                {districts.map((district) => (
                                    <option key={district} value={district}>
                                        {district}
                                    </option>
                                ))}
                            </select>
                        </div>
                    )}
                    {error.district && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.district}</span>}

                    {upazilas && (
                        <div className="inputBox" style={{width:"100%"}}>
                            <select className='form-control'  name="thana" id="thana" onChange={handleChange}>
                                <option value="">Select Thana/Upazila</option>
                                {upazilas.map((upazila) => (
                                    <option key={upazila} value={upazila}>
                                        {upazila}
                                    </option>
                                ))}
                            </select>
                        </div>
                    )}
                    {error.thana && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.thana}</span>}

                    <div className="inputBox">
                        <FiMail className='gender' />
                        <input  className='form-control' type="text"
                            name="gender"
                            id="gender"
                            onChange={handleChange}
                            placeholder='Gender'
                        />
                    </div>
                    {error.gender && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.gender}</span>}

                    <div className="inputBox">
                        <FiMail className='dob' />
                        <input  className='form-control'
                            type="date"
                            name="dob"
                            id="dob"
                            onChange={handleChange}
                            placeholder="Date of Birth"
                        />
                    </div>
                    {error.dob && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.dob}</span>}

                    <div className="inputBox">
                        <RiLockPasswordLine className='password' />
                        <input  className='form-control' type="password"
                            name="password"
                            id="password"
                            onChange={handleChange}
                            placeholder='Password'
                        />
                    </div>
                    {error.password && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.password}</span>}

                    <div className="inputBox">
                        <RiLockPasswordLine className='password' />
                        <input  className='form-control' type="password"
                            name="confirm_password"
                            id="confirm_password"
                            onChange={handleChange}
                            placeholder='Confirm Password'
                        />
                    </div>
                    {error.confirm_password && <span style={{ color: "red", display: "block", marginTop: "5px" }}>{error.confirm_password}</span>}

                    <div className='divBtn'>
                        <small className='FG'><Link to="/forget">Forgot Password?</Link></small>
                        <button className='loginBtn'>SIGN UP</button>
                    </div>
                </form>

                <div className='dont'>
                    <p>Already have an account? <Link to="/"><span>Sign in</span></Link></p>
                </div>
            </div>
        </div>
    );
};
export default SignUp;

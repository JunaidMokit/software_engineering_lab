import {
    Anchor,
    Button,
    Checkbox,
    Container,
    Group,
    Paper,
    PasswordInput,
    Text,
    TextInput,
    Title,
} from '@mantine/core';
import { Helmet } from "react-helmet";
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

const SignupPage = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [emailError, setEmailError] = useState('');
    const [usernameError, setUsernameError] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
   // const [rememberMe, setRememberMe] = useState(false);
    const navigate = useNavigate();

    const validateEmail = (email) => {
        const emailParts = email.split('@');
        if (emailParts.length !== 2) {
            setEmailError('Invalid email format');
            return false;
        }

        const [localPart, domainPart] = emailParts;

        if (!domainPart.endsWith('.uiu.ac.bd')) {
            setEmailError('Email must end with ".uiu.ac.bd"');
            return false;
        }

        const emailRegex = /^[a-zA-Z]+[0-9]{6,7}@[a-zA-Z]+\.uiu\.ac\.bd$/;

        if (!emailRegex.test(email)) {
            setEmailError('Give Official UIU Email');
            return false;
        }
        setEmailError('');
        return true;
    };
        const [valid, setValid] = useState(false);
        const validateUsername = async (username) => {
            try {
                const response = await fetch(`http://localhost:3000/auth/${username}`);
                const data = await response.json();
                
        
                if (data.exists) {  
                    setValid(true);
                    setUsernameError('Username already exists');
                    console.log("not working 2");
                } else {
                    setValid(false);
                    setUsernameError('');
                }
            } catch (error) {
                console.error('Error checking username:', error);
                setUsernameError('Error occurred while checking username');
            }
        
            return valid; 
        };
        const check = async (username) => {
            await validateUsername(username);
        };
            
        

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (!validateEmail(email)) {
            return;
        }
        check(username);
        if(valid){
            return;
        }        
        const response = await fetch('http://localhost:3000/auth/sign', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name,
                email,
                username,
                password,
            }),
        });

        const data = await response.json();
        console.log(data);

        if (response.ok) {
            console.log('Signup successful:', data);
            navigate('/login');
        } else {
            console.error('Signup failed:', data);
            alert(`Signup failed: ${data.error}`);
        }
    };

    return (
        <>
            <Helmet>
                <title>Signup</title>
            </Helmet>
            <Container size={420} my={40}>
                <Title sx={{ fontWeight: 900, textAlign: 'center', whiteSpace: 'nowrap' }}>
                    Welcome to FundWave!
                </Title>

                <Text color="dimmed" size="sm" align="center" mt={5}>
                    Already have an account?{' '}
                    <Anchor size="sm" component="button">
                        <Link to="/login">Login</Link>
                    </Anchor>
                </Text>

                <Paper withBorder shadow="md" p={30} mt={30} radius="md" component="form" onSubmit={handleSubmit}>
                    <TextInput label="Name" placeholder="Your name" required value={name} onChange={(e) => setName(e.target.value)} />
                    <TextInput 
                        label="Email" 
                        placeholder="Your email" 
                        required 
                        mt="md" 
                        value={email} 
                        onChange={(e) => setEmail(e.target.value)} 
                        error={emailError} 
                    />
                    <TextInput label="Username" placeholder="Your Username" required mt="md" value={username} onChange={(e) => setUsername(e.target.value)} error={usernameError} />
                    <PasswordInput label="Password" placeholder="Your password" required mt="md" value={password} onChange={(e) => setPassword(e.target.value)} />
                    <Group position="apart" mt="lg">
                         {/* <Checkbox label="Remember me" checked={rememberMe} onChange={(e) => setRememberMe(e.currentTarget.checked)} /> */} 
                        <Anchor component="button" size="sm">
                        <Link to='/forgot/recovered'>

                            Forgot password?
                            </Link>
                        </Anchor> 
                    </Group>
                    <Button type="submit" fullWidth mt="xl">
                        Sign Up
                    </Button>
                </Paper>
            </Container>
        </>
    );
};

export default SignupPage;

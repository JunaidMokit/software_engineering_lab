import React, { useState, useEffect,useRef } from 'react';
import io from 'socket.io-client';
// import Nav from '../../../Nostalgia-Frontend/src/Components/Navigation/Nav';
import { useLocation, useParams } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import './Chat.css';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { FaReact } from 'react-icons/fa';

const useSocket = (url) => {
    const [socket, setSocket] = useState(null);
    useEffect(() => {
        const socketInstance = io(url);
        setSocket(socketInstance);

        return () => {
            socketInstance.disconnect();
        };
    }, [url]);

    return socket;
};
const Chat = () => {
    const { fnd } = useParams();
    const [fd, setfd] = useState("");
    const location = useLocation();
    const username = localStorage.getItem('username');
    const [done, setdone] = useState(false);
    const [users, setUsers] = useState([]);
    const [userbox, setUserbox] = useState([]);
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [search, setSearch] = useState('');
    const [showMenu, setShowMenu] = useState(false);
    const socket = useSocket(`http://localhost:5000`);
    const [lastseen, setLastseen] = useState("");
    
    useEffect(() => {
        if (fnd && !done) {
            console.log("fnd alreadt set   "+fnd);
            setfd(fnd);
            findname(fnd);
            msgbox();
        }

    }, [fnd,done]);
    // console.log(fnd)
    const finduserlist = async () => {
        try {
            const response = await axios.get(`http://localhost:5000/api/userbox/` + username);
            const userList = response.data.map((user, index) => ({
                id: index + 1,
                name: user.username,
                online: user.online,
                lastSeen: user.lastSeen
            }));
    
            setUsers(userList);
    
            if (userList.length > 0 && (fnd == "" || fnd == null || fnd == undefined) && !done) {
                console.log(fnd);
                setLastseen(userList[0].lastSeen);
                console.log("set of userlists")
                setfd(userList[0].name);
                msgbox();
                findname(userList[0].name);
            }
    
            // Fetch user images after fetching user list
            fetchUserImages(userList);
        } catch (error) {
            console.error('Error fetching users:', error);
        }
    };
    
    const fetchUserImages = async (userList) => {
        const userImages = await Promise.all(userList.map(async (user) => {
            try {
                return await fetchUserImage(user.name, username);
            } catch (error) {
                console.error('Error fetching user image:', error);
                return null;
            }
        }));
    
        const updatedUserBox = userList.map((user, index) => ({
            id: user.id,
            name: user.name,
            online: user.online,
            lastSeen: user.lastSeen,
            img: userImages[index]
        }));
        setUserbox(updatedUserBox);
    };
    
    async function fetchUserImage(username, currentUser) {
        try {
            const response = await axios.get(`http://localhost:3000/auth/user/${username}`, {
            });
            return response.data.img;
        } catch (error) {
            console.error('Error fetching user image:', error);
            return null;
        }
    }    
    useEffect(()=>{
        if (!socket) return;
        socket.on('users status', (usersStatus) => {
            // Handle received user status updates
            // console.log('Received user status:', usersStatus);
            // console.log("user data",userbox);
            setUserbox(prevUserBox => {
                return prevUserBox.map(user => {
                    const status = usersStatus.find(status => status.username.toLowerCase() === user.name.toLowerCase());
                    if (status) {
                        // Update user's status and last seen time
                        return {
                            ...user,
                            online: status.online,
                            lastSeen: status.online ? '' : status.lastSeen
                        };
                    }
                    return user;
                });
                
            });
          //  console.log("updated userbox ",userbox);
                                
            // You can update your UI or perform any other actions based on the received user status
        });

    }, [socket, messages]);

    useEffect(() => {
        if (!socket) return;
        
        socket.on('connect', () => {
            console.log('Socket connected');
        });
        socket.on('disconnect', () => {
            console.log('Socket disconnected');
        })
        
        socket.on('chat message', (message) => {
            // console.log('New message received from:', message.sender);
            // console.log('New message received:', message);
            const messageExists = messages.some(msg => msg.id == msg.id);
            if ( (message.sender == username || (message.sender.toLowerCase() == String(fd).toLowerCase()) && String(message.receiver).toLowerCase() == String(username).toLowerCase())) {
                // console.log("after rcv msg");
                setMessages(prevMessages => [...prevMessages, message]);
                const chatHistory = document.getElementById('chat-history');
                chatHistory.scrollTop = chatHistory.scrollHeight - chatHistory.clientHeight;    
            }
        });
           
        
        return () => {
            socket.off('connect');
            socket.off('disconnect');
            socket.off('chat message');
        };
    }, [socket, messages]);


    useEffect(() => {
        const handleBeforeUnload = () => {
            console.log('Leaving page, disconnecting socket');
           socket.disconnect();
        };

        const handlePageFocus = () => {
            console.log('Returning to page, reconnecting socket');
            socket.connect();
        };
        window.addEventListener('beforeunload', handleBeforeUnload);
        window.addEventListener('focus', handlePageFocus);
        return () => {
            window.removeEventListener('beforeunload', handleBeforeUnload);
            window.removeEventListener('focus', handlePageFocus);
        };
    }, [socket]);
    const [selectedImage, setSelectedImage] = useState(null);

    const handleImageSelect = (event) => {
        const file = event.target.files[0];
        setSelectedImage(file);
        //sendMessage();
    };


    const sendMessage = () => {
        if (selectedImage) {
            // Create a FormData object to send the image file
            const formData = new FormData();
            formData.append('image', selectedImage);

            // Send the FormData object along with other message data
            const message = {
                id: messages.length + 1,
                sender: username,
                receiver: fd,
                content: '', // You can include a message if needed
                time: new Date().toLocaleTimeString(),
                date: new Date().toLocaleDateString(),
                img:1,
                image: formData, // Attach the FormData object containing the image
            };
            console.log(message.image);

            // Emit the message event to the server
            socket.emit('chat message', message);
            setNewMessage('');
            // Clear the selected image after sending
            setSelectedImage(null);
        }else if (newMessage.trim() !== '') {
            
            const message = {
                id: messages.length + 1,
                sender: username,
                receiver: fd,
                content: newMessage,
                time: new Date().toLocaleTimeString(),
                date: new Date().toLocaleDateString(),
                img:0,
                image: null
            };
            socket.emit('set username', username);
            socket.emit('chat message', message);    
            setNewMessage('');
                  // Save message to MongoDB using Axios
        axios.post(`http://localhost:5000/api/messages`, message)
        .then(response => {
            console.log('Message saved:', response.data);
        })
        .catch(error => {
            console.error('Error saving message:', error);
        });
        }
    };
    const msgbox = async () => {
        axios.get(`http://localhost:5000/api/messages/`, {
            params: {
                id1: username,
                id2: fd
            }
        })
        .then(response => {
            console.log('Message Retrieve:', response.data);
            setMessages(response.data);
            const user = userbox.find(user => user.name === fd);
            setLastseen(user ? user.lastSeen : lastseen);
            
        })
        .catch(error => {
            console.error('Error fetching messages:', error);
        });
        const chatHistory = document.getElementById('chat-history');
        chatHistory.scrollTop = chatHistory.scrollHeight - chatHistory.clientHeight;

    }
    
    useEffect(() => {
        if (fd) {
            msgbox();
            findname(fd);
        } 
    }, [fd]);
    
    const [fnddata, setfndData] = useState("");
    const [fndname, setfndName] = useState("");
    const findname = (name) => {
        // console.log(name);
        // if (name==null)return;
        axios.get(`http://localhost:3000/auth/user/${name}`).then(response => {
            console.log('Box of User Data:', response.data);
            setfndData(response.data);
            setfndName(response.data.name);
            const user = userbox.find(user => user.name === name);
            setLastseen(user ? user.lastSeen : lastseen);
                        console.log(name);
            console.log(userbox);
            console.log("last seen time update in findname",lastseen);
            console.log(response.data.first_name + " " + response.data.last_name);
        })
        .catch(error => {
            console.error('Error fetching user data:', error);
        });
    };
  const handleNameClick = (name) => {
        setdone(true);
        setfd(name);
        findname(name);
        msgbox();
        console.log("msg box of : "+name);
    }; 
    useEffect(() => {
        finduserlist();
    // }, [fndname,fd,userData.username,messages,socket]);
  }, [socket,fd]);
  const chatHistoryRef = useRef(null);
  const scrollToBottom = () => {
    if (chatHistoryRef.current) {
      chatHistoryRef.current.scrollTop = chatHistoryRef.current.scrollHeight;
      console.log("scorlling");
    }
  };
function getLastSeenTime(lastSeen) {
    const currentTime = new Date();
    const lastSeenTime = new Date(lastSeen);
    const timeDifference = currentTime.getTime() - lastSeenTime.getTime();
    const seconds = Math.floor(timeDifference / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30);
    const years = Math.floor(months / 12);

    if (years > 0) {
        return `left ${years} year${years > 1 ? 's' : ''} ago`;
    } else if (months > 0) {
        return `left ${months} month${months > 1 ? 's' : ''} ago`;
    } else if (days > 0) {
        return `left ${days} day${days > 1 ? 's' : ''} ago`;
    } else if (hours > 0) {
        return `left ${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else if (minutes > 0) {
        return `left ${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else {
        return `left a few seconds ago`;
    }
}
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

    return (
        <div className='interface'>
            {username?.includes("@") ? (
                <>
                <h1 className="error mt-4">You are not allowed to view this page</h1>
                </>
            ) : (
            <div className='bot mt-2' style={{ position: 'fixed', marginBottom: '20px' }}>
                <div className='row clearfix'>
                    <div className='card chat-app'>
                        <div className='col-lg-3'>
                            <div id='plist' className='people-list'>
                                <h2>Recent Message</h2>
                                <div className='input-group'>
                                    {/* <div className='input-group-prepend'>
                                        <span className='input-group-text' style={{ height: '38px' }}>
                                            <i className='fas fa-search' style={{ fontSize: '16px' }}></i>
                                        </span>
                                    </div> */}
                                    {/* <input type='text' className='form-control' style={{ height: '38px' }} placeholder='Search...' /> */}
                                </div>
                                <hr />
                                <ul className='list-unstyled chat-list mt-2 mb-0' style={{ maxHeight: '500px', overflowY: 'auto', marginBottom: '20px' }}>
                                {userbox.map((user) => (
                                    <li key={user.id} className='clearfix'  onClick={() => handleNameClick(user.name)}>
                                        <img src={`http://localhost:3000/api/campaign${user.img}`} alt='avatar' className="circle" style={{ width: '50px', height: '50px' }} />
                                        <div className='about'>
                                            <div className='name'>
                                                {user.name}
                                            </div>
                                            <div className="status">
                                                <i className={`fa fa-circle ${user.online ? 'online' : 'offline'}`}></i> {user.online ? 'Online' : getLastSeenTime(user.lastSeen)}
                                            </div>
                                        </div>
                                    </li>
                                ))}
                                </ul>
                            </div>
                        </div>
                        <div className='chat'>
                            <div className='chat-header clearfix'>
                                <div className='row'>
                                    <div className='col-lg-6'>
                                        <a href='javascript:void(0);' data-toggle='modal' data-target='#view_info'>
                                        <img src={`http://localhost:3000/api/campaign${fnddata.img}`} alt='avatar' className="circle" style={{ width: '50px', height: '50px' }} />
                                        </a>
                                        <div className='chat-about'>
                                        <Link to={`/profile/${fd}`} className="text-dark">
                                            <h6 className='m-b-0'>{fndname}</h6>
                                            <small> {fd && userbox.find(user => user.name === fd)?.online ? 'online' : getLastSeenTime(lastseen)}</small>
                                            </Link>
                                        </div>
                                    </div>
                                    <div className='col-lg-6 box-right'>
                                        <a href='javascript:void(0);' className='btn btn-outline-secondary'>
                                            <i className='fas fa-camera'></i>
                                        </a>
                                        <a href='javascript:void(0);' className='btn btn-outline-primary'>
                                            <i className='fas fa-image'></i>
                                        </a>
                                        <a href='javascript:void(0);' className='btn btn-outline-info'>
                                            <i className='fas fa-cogs'></i>
                                        </a>
                                        <a href='javascript:void(0);' className='btn btn-outline-warning'>
                                            <i className='fas fa-question'></i>
                                        </a>
                                    </div>
                                </div>
                            </div>
                            <div className='chat-history' ref={chatHistoryRef}  id='chat-history' style={{ height: '420px', overflowY: 'scroll' }}>
                                <ul className='m-b-0' >
                                 {messages.map((message, index) => (
                                        <li key={index} className='clearfix'>
                                            {message.sender == username ? (
                                                <>
                                                    <div className="message-data box-right">
                                                        <span className="message-data-time m-2">{message.time}</span>
                                                    {/* <img src={`http://localhost:8000/${userData.p_image}`} alt="User" className="circle" style={{ width: '50px', height: '50px' }} /> */}
                                                  <br/>
                                                    <div className="message my-message msg-right bg-primary text-light">{message.content}</div> 
                                                     </div>
                                                                                                </>
                                            ) : (
                                                <>
                                                    <div className="message-data">
                                                        <span className="message-data-time">{message.time}</span>
                                                  
                                                 <br/>
                                                    <div className="message my-message bg-dark text-light">{message.content}</div>
                                                    </div>
                                                
                                                </>
                                            )}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                            <div className='chat-message clearfix'>
                                <div className='input-group mb-0'>
                                    {/* <div className='input-group-prepend'>
                                        <span className='input-group-text' style={{ height: '38px' }}>
                                            <i className='fas fa-paper-plane' style={{ fontSize: '16px' }}></i>
                                        </span>
                                    </div> */}
                                          <div className="input-group-prepend" style={{ width: '40px', height: '48px', position: 'relative' }}>
                                                            <input
                                                                type="file"
                                                                accept="image/*"
                                                                onChange={handleImageSelect}
                                                                style={{ opacity: 0, position: 'absolute', width: '100%', height: '100%', zIndex: 1, cursor: 'pointer' }}
                                                            />
                                                            <FaReact style={{ width: '100%', height: '100%', color: '#61dafb', pointerEvents: 'none' }} />
                                                            </div>

                                    <input
                                        type='text'
                                        className='form-control'
                                        style={{ height: '48px' }}
                                        placeholder='Enter text here...'
                                        value={newMessage}
                                        onChange={(e) => setNewMessage(e.target.value)}
                                        onKeyDown={(e) => {
                                            if (e.key === 'Enter') {
                                                sendMessage();
                                            }
                                        }}
                                    />
                                    <div className='input-group-append'>
                                        <button className='btn btn-primary' style={{ height: '48px' }}  type='button' onClick={sendMessage}>
                                            Send
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            )}
        </div>
    );
};


export default Chat;
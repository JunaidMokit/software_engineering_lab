// import React, { useEffect, useState, useRef } from 'react';
// import axios from 'axios';
// //import { FaReact } from 'react-icons/fa';
// //import { Link } from 'react-router-dom';
// //import io, { Socket } from 'socket.io-client';
// // import Nav from './Nav'; // Assuming you have a Nav component
// // import { User, Message, APIResponse } from './types'; // Import types from a types file

// interface ChatProps {
//   userData: { username: string };
//   api: { url: string };
// }

// const Chat: React.FC<ChatProps> = ({ userData, api }) => {
//   const [search, setSearch] = useState<string>('');
//   const [showMenu, setShowMenu] = useState<boolean>(false);
//   const [userbox, setUserbox] = useState<User[]>([]);
//   const [fd, setFd] = useState<string>('');
//   const [messages, setMessages] = useState<Message[]>([]);
//   const [newMessage, setNewMessage] = useState<string>('');
//   const [lastseen, setLastseen] = useState<string>('');
//   const [done, setDone] = useState<boolean>(false);
//   const [socket, setSocket] = useState<Socket | null>(null);
//   const [selectedImage, setSelectedImage] = useState<File | null>(null);
//   const [fnddata, setFndData] = useState<APIResponse | null>(null);
//   const [fndname, setFndName] = useState<string>('');

//   const chatHistoryRef = useRef<HTMLDivElement>(null);

//   // Handle userbox update (deletion of a user)
//   const handleUserboxUpdate = (username: string) => {
//     console.log('delete krobo', username);
//     const updatedUserbox = userbox.filter((user) => user.name !== username);
//     setUserbox(updatedUserbox);
//   };

//   // Scroll to the bottom of the chat
//   const scrollToBottom = () => {
//     if (chatHistoryRef.current) {
//       chatHistoryRef.current.scrollTop = chatHistoryRef.current.scrollHeight;
//       console.log('Scrolling');
//     }
//   };

//   // Retrieve last seen time logic
//   function getLastSeenTime(lastSeen: string): string {
//     const currentTime = new Date();
//     const lastSeenTime = new Date(lastSeen);
//     const timeDifference = currentTime.getTime() - lastSeenTime.getTime();
//     const seconds = Math.floor(timeDifference / 1000);
//     const minutes = Math.floor(seconds / 60);
//     const hours = Math.floor(minutes / 60);
//     const days = Math.floor(hours / 24);
//     const months = Math.floor(days / 30);
//     const years = Math.floor(months / 12);

//     if (years > 0) {
//       return `left ${years} year${years > 1 ? 's' : ''} ago`;
//     } else if (months > 0) {
//       return `left ${months} month${months > 1 ? 's' : ''} ago`;
//     } else if (days > 0) {
//       return `left ${days} day${days > 1 ? 's' : ''} ago`;
//     } else if (hours > 0) {
//       return `left ${hours} hour${hours > 1 ? 's' : ''} ago`;
//     } else if (minutes > 0) {
//       return `left ${minutes} minute${minutes > 1 ? 's' : ''} ago`;
//     } else {
//       return `left a few seconds ago`;
//     }
//   }

//   // Send message logic
//   const sendMessage = () => {
//     if (selectedImage) {
//       const formData = new FormData();
//       formData.append('image', selectedImage);

//       const message: Message = {
//         id: messages.length + 1,
//         sender: userData.username,
//         receiver: fd,
//         content: '',
//         time: new Date().toLocaleTimeString(),
//         date: new Date().toLocaleDateString(),
//         img: 1,
//         image: formData,
//       };
//       socket?.emit('chat message', message);
//       setNewMessage('');
//       setSelectedImage(null);
//     } else if (newMessage.trim() !== '') {
//       const message: Message = {
//         id: messages.length + 1,
//         sender: userData.username,
//         receiver: fd,
//         content: newMessage,
//         time: new Date().toLocaleTimeString(),
//         date: new Date().toLocaleDateString(),
//         img: 0,
//         image: null,
//       };
//       socket?.emit('chat message', message);
//       setNewMessage('');

//       // Save message to MongoDB using Axios
//       axios.post(`${api.url}:5000/api/messages`, message)
//         .then((response) => {
//           console.log('Message saved:', response.data);
//         })
//         .catch((error) => {
//           console.error('Error saving message:', error);
//         });
//     }
//   };

//   // Retrieve chat messages
//   const msgbox = () => {
//     axios
//       .get(`${api.url}:5000/api/messages/`, {
//         params: {
//           id1: userData.username,
//           id2: fd,
//         },
//       })
//       .then((response) => {
//         console.log('Message Retrieve:', response.data);
//         setMessages(response.data);
//         const user = userbox.find((user) => user.name === fd);
//         setLastseen(user ? user.lastSeen : lastseen);
//       })
//       .catch((error) => {
//         console.error('Error fetching messages:', error);
//       });
//     scrollToBottom();
//   };

//   useEffect(() => {
//     if (fd) {
//       msgbox();
//       findname(fd);
//     }
//   }, [fd]);

//   // Find user by name
//   const findname = (name: string) => {
//     axios
//       .get(`${api.url}:8000/profile/${name}`, {
//         params: {
//           username: name,
//           user: userData.username,
//         },
//       })
//       .then((response) => {
//         console.log('Box of User Data:', response.data);
//         setFndData(response.data);
//         setFndName(`${response.data.first_name} ${response.data.last_name}`);
//         const user = userbox.find((user) => user.name === name);
//         setLastseen(user ? user.lastSeen : lastseen);
//       })
//       .catch((error) => {
//         console.error('Error fetching user data:', error);
//       });
//   };

//   // Handle name click
//   const handleNameClick = (name: string) => {
//     setDone(true);
//     setFd(name);
//     findname(name);
//     msgbox();
//   };

//   useEffect(() => {
//     scrollToBottom();
//   }, [messages]);

//   return (
//     <div className='interface'>
//       <Nav search={search} setSearch={setSearch} showMenu={showMenu} setShowMenu={setShowMenu} />
//       {userData.username.includes('@') ? (
//         <h1 className='error mt-4'>You are not allowed to view this page</h1>
//       ) : (
//         <div className='bot mt-2' style={{ position: 'fixed', marginBottom: '20px' }}>
//           <div className='row clearfix'>
//             <div className='card chat-app'>
//               <div className='col-lg-3'>
//                 <div id='plist' className='people-list'>
//                   <h2>Recent Message</h2>
//                   <hr />
//                   <ul className='list-unstyled chat-list mt-2 mb-0' style={{ maxHeight: '500px', overflowY: 'auto', marginBottom: '20px' }}>
//                     {userbox.map((user) => (
//                       <li key={user.id} className='clearfix' onClick={() => handleNameClick(user.name)}>
//                         <img src={`${api.url}:8000/${user.img}`} alt='avatar' className='circle' style={{ width: '50px', height: '50px' }} />
//                         <div className='about'>
//                           <div className='name'>{user.name}</div>
//                           <div className='status'>
//                             <i className={`fa fa-circle ${user.online ? 'online' : 'offline'}`}></i> {user.online ? 'Online' : getLastSeenTime(user.lastSeen)}
//                           </div>
//                         </div>
//                       </li>
//                     ))}
//                   </ul>
//                 </div>
//               </div>
//               <div className='chat'>
//                 <div className='chat-header clearfix'>
//                   <div className='row'>
//                     <div className='col-lg-6'>
//                       <a href='javascript:void(0);' data-toggle='modal' data-target='#view_info'>
//                         <img src={`${api.url}:8000/${fnddata?.pp}`} alt='avatar' className='circle' style={{ width: '50px', height: '50px' }} />
//                       </a>
//                       <div className='chat-about'>
//                         <Link to={`/profile/${fd}`} className='text-dark'>
//                           <h6 className='m-b-0'>{fndname}</h6>
//                           <small>{fd && userbox.find((user) => user.name === fd)?.online ? 'online' : getLastSeenTime(lastseen)}</small>
//                         </Link>
//                       </div>
//                     </div>
//                     <div className='col-lg-6 hidden-sm text-right'>
//                       <FaReact />
//                     </div>
//                   </div>
//                 </div>
//                 {/* Chat Body */}
//                 <div className='chat-history' ref={chatHistoryRef} style={{ height: '400px', overflowY: 'auto' }}>
//                   <ul className='m-b-0'>
//                     {messages.map((message) => (
//                       <li className='clearfix' key={message.id}>
//                         <div className={`message-data text-right`}>
//                           <span className='message-data-time'>{message.time}, {message.date}</span>
//                           <img src={`${api.url}:8000/${message.img}`} alt='avatar' className='circle' style={{ width: '50px', height: '50px' }} />
//                         </div>
//                         <div className={`message ${message.sender === userData.username ? 'other-message float-right' : 'my-message'}`}>
//                           {message.content}
//                           {message.img === 1 && <img src={URL.createObjectURL(selectedImage!)} alt='Selected' style={{ maxWidth: '200px', maxHeight: '200px' }} />}
//                         </div>
//                       </li>
//                     ))}
//                   </ul>
//                 </div>
//                 <div className='chat-message clearfix'>
//                   <div className='input-group mb-0'>
//                     <input type='file' onChange={(e) => setSelectedImage(e.target.files?.[0] || null)} className='btn mt-1 mr-1' />
//                     <input type='text' className='form-control' placeholder='Enter text here...' value={newMessage} onChange={(e) => setNewMessage(e.target.value)} />
//                     <button className='btn btn-primary' onClick={sendMessage}>Send</button>
//                   </div>
//                 </div>
//               </div>
//             </div>
//           </div>
//         </div>
//       )}
//     </div>
//   );
// };

// export default Chat;

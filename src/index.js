import http from 'http';
import { Server } from 'socket.io';
import app from './app';
import formatMessage from './utils/chat/messages';
import {
  userJoin,
  getCurrentUser,
  userLeave,
  getRoomUsers,
} from './utils/chat/users';

const port = process.env.PORT || 3000;
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

const botName = 'Barefoot Bot';

// Run when client connects
io.on('connection', (socket) => {
  socket.on('joinRoom', ({ username }) => {
    const user = userJoin(socket.id, username);

    socket.join(user.room);

    // Welcome current user
    socket.emit(
      'message',
      formatMessage(botName, 'Welcome to Barefoot Nomad Chat!')
    );

    // Broadcast when a user connects
    socket.broadcast
      .to(user.room)
      .emit(
        'message',
        formatMessage(botName, `${user.username} has joined the chat`)
      );

    // Send users and room info
    io.to(user.room).emit('roomUsers', {
      room: user.room,
      users: getRoomUsers(user.room),
    });
  });

  // Listen for chatMessage
  socket.on('chatMessage', (msg) => {
    const user = getCurrentUser(socket.id);

    io.to(user.room).emit('message', formatMessage(user.username, msg));
  });

  // Runs when client disconnects
  socket.on('disconnect', () => {
    const user = userLeave(socket.id);

    if (user) {
      io.to(user.room).emit(
        'message',
        formatMessage(botName, `${user.username} has left the chat`)
      );

      // Send users and room info
      io.to(user.room).emit('roomUsers', {
        room: user.room,
        users: getRoomUsers(user.room),
      });
    }
  });
});

server.listen(port, () => {
  console.log(`Server listening on port ${port}`);
  console.log(`Running on ${process.env.NODE_ENV || 'Production'} Server`);
});

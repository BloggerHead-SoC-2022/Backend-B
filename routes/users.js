const express = require('express');
const router = express.Router();
const db = require('../models/userModel');
const bcrypt = require('bcrypt');
const createJWT = require('../utils/auth');

const regexEmail = new RegExp(/^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$/);
const regexUsername = new RegExp(/^[a-zA-Z0-9_]+$/);
const regexPassword = new RegExp(/^.{8,}$/);
const regexName = new RegExp(/^[A-Za-z]+$/);

router.get('/', async (req, res) => {
    try{
        const allUsers = await db.find();
        res.json(allUsers);
    } catch(e){
        res.send('error' + e)
    }
});

router.get('/:id', async (req, res) => {
    try{
        const User1 = await db.findById(req.params.id);
        res.json(User1);
    } catch(e){
        res.send('error' + e)
    }
});

router.post('/signup', async (req, res) => {

    if(!req.body.username || !req.body.emailId || !req.body.password || !req.body.password_confirm || !req.body.firstname || !req.body.lastname){
        return res.status(400).json({ msg: 'Please include a username, emailId, firstname, lastname, password and password_confirm ' });
    }

    const theUser1 = await db.findOne({ username: req.body.username });
    if(theUser1){
        return res.status(400).json({ msg: 'The username has been taken, please choose another username!' });
    }

    const theUser2 = await db.findOne({ emailId: req.body.emailId });
    if(theUser2){
        return res.status(400).json({ msg: 'Already an account exists from this Email ID!' });
    }

    if(!regexName.test(req.body.firstname)){
        return res.status(400).json({ msg: 'Please provide us with a valid name' });
    };

    if(!regexName.test(req.body.lastname)){
        return res.status(400).json({ msg: 'Please provide us with a valid name' });
    };

    if(!regexUsername.test(req.body.username)){
        return res.status(400).json({ msg: 'The username can only contain alphabets, numbers and _ ' });
    };

    if(!regexEmail.test(req.body.emailId)){
        return res.status(400).json({ msg: 'Please provide us with a valid email ID!' });
    };

    if(!regexPassword.test(req.body.password)){
        return res.status(400).json({ msg: 'The password should be atleast 8 characters long!' });
    };

    if(req.body.password != req.body.password_confirm){
        return res.status(400).json({ msg: 'The password does not matches with password_confirm!' });
    }
    
    const newUsers = new db({
        username: req.body.username,
        password: req.body.password,
        emailId: req.body.emailId,
        firstname: req.body.firstname,
        lastname: req.body.lastname
    });

    const salt = await bcrypt.genSalt(10);

    newUsers.password = await bcrypt.hash(newUsers.password, salt);

    try{
        await newUsers.save();
        const allUsers = await db.find();
        res.json(allUsers);
    } catch(e){
        res.send('error' + e)
    }
});

router.post('/signin', async (req, res) => {

    if(!req.body.username || !req.body.password){
        return res.status(400).json({ msg: 'Please provide username and password to successfully sign in!' });
    }

    const User = await db.findOne({ username: req.body.username });
    if(User){
        const passValid = await bcrypt.compare(req.body.password, User.password);
        if(passValid){
            let jwt_token = createJWT(User.username, User.password);
            res.status(200).json({ message: `Welcome back! ${User.firstname} ${User.lastname} aka ${User.username}`, jwt_token, User });
        }
        else{
            return res.status(400).json({ msg: 'Incorrect Password!!!' });
        }
    }
    else{
        return res.status(400).json({ msg: `No user with the username ${req.body.username} exists!` });
    }

});

router.put('/:id', async (req, res) => {
    const newUser = req.body;

    try{
        const oldUser = await db.findById(req.params.id);


        const theUser3 = await db.findOne({ emailId: req.body.emailId });
        if(theUser3){
            
            if(theUser3.emailId===oldUser.emailId){   
                oldUser.emailId = newUser.emailId;
            }
            else{
                return res.status(400).json({ msg: "Already an account exists from this Email ID!"});
            }
        }
        else{
            if(!regexEmail.test(newUser.emailId)){
                return res.status(400).json({ msg: 'Please provide us with a valid email ID!' });
            }
            oldUser.emailId = newUser.emailId;
        }


        if(newUser.firstname){
            if(!regexName.test(newUser.firstname)){
                return res.status(400).json({ msg: 'Please provide us with a valid name' });
            }
            oldUser.firstname = newUser.firstname;
        }
        else{
            oldUser.firstname = oldUser.firstname;
        }


        if(newUser.lastname){
            if(!regexName.test(newUser.lastname)){
                return res.status(400).json({ msg: 'Please provide us with a valid name' });
            }
            oldUser.lastname = newUser.lastname;
        }
        else{
            oldUser.lastname = oldUser.lastname;
        }


        const theUser4 = await db.findOne({ username: req.body.username });
        if(theUser4){
            if(theUser4.username===oldUser.username){   
                oldUser.username = newUser.username;
            }
            else{
                return res.status(400).json({ msg: 'The username has been taken, please choose another username!' });
            }
        }
        else{
            if(!regexUsername.test(newUser.username)){
                return res.status(400).json({ msg: 'The username can only contain alphabets, numbers and _ ' });
            }
            oldUser.username = newUser.username;
        }





        if(!newUser.oldPassword && (newUser.newPassword || newUser.password_confirm)){
            return res.status(400).json({ msg: 'If you want to update the password, then please provide us with your current password!' });
        }
        if(newUser.oldPassword){
            const pass = await bcrypt.compare(newUser.oldPassword, oldUser.password);
            if(pass){
                if(newUser.newPassword && !newUser.password_confirm){
                    return res.status(400).json({ msg: 'If you want to update the password, then please also provide password_confirm' });
                }
                else if(!newUser.newPassword && newUser.password_confirm){
                    return res.status(400).json({ msg: 'If you want to update the password, then please also provide New Password' });
                }
                else if(newUser.newPassword && newUser.password_confirm){
                    if(newUser.newPassword != newUser.password_confirm){
                        return res.status(400).json({ msg: 'The password does not matches with password_confirm!' });
                    }
                    if(!regexPassword.test(newUser.newPassword)){
                        return res.status(400).json({ msg: 'The password should be atleast 8 characters long!' });
                    };
                    const salt = await bcrypt.genSalt(10);
                    newUser.newPassword = await bcrypt.hash(newUser.newPassword, salt);
                    oldUser.password = newUser.newPassword;
                }
                else{
                    oldUser.password = oldUser.password;
                }
            }
            else{
                return res.status(400).json({ msg: 'The password is incorrect!' });
            }
        }
        else{
            oldUser.password = oldUser.password;
        }

        await oldUser.save();
        //const allUsers = await db.find();
        res.status(200).json({oldUser});
    } catch(e){
        res.send('error' + e)
    }
});

router.delete('/:id', async (req, res) => {
    try{
        const oldUser = await db.findById(req.params.id);
        await oldUser.remove();
        const allUsers = await db.find();
        res.json(allUsers);
    } catch(e){
        res.send('error' + e)
    }
});

module.exports = router;

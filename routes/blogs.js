const express = require('express');
const router = express.Router();
const blogDB = require('../models/blogModel');

router.get('/', async (req, res) => {
    try{
        const allBlogs = await blogDB.find().sort({ updatedAt:-1 });
        res.json(allBlogs);
    } catch(e){
        res.send('error' + e)
    }
});

router.get('/:id', async (req, res) => {
    try{
        const Blog1 = await blogDB.findById(req.params.id);
        res.json(Blog1);
    } catch(e){
        res.send('error' + e)
    }
});

router.post('/', async (req, res) => {

    if(!req.body.title || !req.body.author || !req.body.content){
        return res.status(400).json({ msg: 'Please include a title, author and content' });
    }

    const newBlog = new blogDB({
        title: req.body.title,
        author: req.body.author,
        content: req.body.content,
        userId: req.body.userId
    });

    try{
        await newBlog.save();
        const allBlogs = await blogDB.find();
        res.json(allBlogs);
    } catch(e){
        res.send('error' + e)
    }
});

router.put('/:id', async (req, res) => {
    const updBlog = req.body;

    try{
        const oldBlog = await blogDB.findById(req.params.id);
        oldBlog.title = updBlog.title ? updBlog.title: oldBlog.title;
        oldBlog.author = updBlog.author ? updBlog.author: oldBlog.author;
        oldBlog.content = updBlog.content ? updBlog.content: oldBlog.content;
        oldBlog.userId = updBlog.userId ? updBlog.userId: oldBlog.userId;
        await oldBlog.save();
        //const allBlogs = await blogDB.find();
        res.status(200).json({oldBlog});
    } catch(e){
        res.send('error' + e)
    }
});

router.delete('/:id', async (req, res) => {
    try{
        const oldBlog = await blogDB.findById(req.params.id);
        await oldBlog.remove();
        const allBlogs = await blogDB.find();
        res.json(allBlogs);
    } catch(e){
        res.send('error' + e)
    }
});

module.exports = router;

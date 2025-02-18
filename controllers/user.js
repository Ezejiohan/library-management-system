const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { fetchUser, createUser } = require('../repository/user')

exports.signup = async (req, res) => {
    try {   
        const { fullname, email, password, phone } = req.body;
    
        const existingSuperAdmin = await fetchUser({ role: 'super_admin' });

        let role = existingSuperAdmin ? 'borrower' : 'super_admin';

        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const user = await createUser({ 
            fullname, 
            email, 
            password: hashedPassword, 
            phone, 
            role 
        });

        await user.save();
        res.status(201).json({ message: 'User registered successfully', user });
    
    } catch (error) {
        res.status(500).json({ error: error.message });   
    }
};


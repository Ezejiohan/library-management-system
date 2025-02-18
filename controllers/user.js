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

exports.login = async (req, res) => {
    const { email, password } = req.body;
    const user = await fetchUser({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const generatedToken = jwt.sign({ 
        userId: user._id, 
        role: user.role 
    }, 
    process.env.TOKEN, { expiresIn: '1d' });
    const result = {
        userId: user._id,
        email: user.email,
        token: generatedToken,
    };

    return res.status(200).json({ result });
};

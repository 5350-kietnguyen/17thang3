var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const { check_authentication } = require('../Utils/check_auth');
const bcrypt = require('bcrypt');

router.post('/signup', async function(req, res, next) {
    try {
        let body = req.body;
        let result = await userController.createUser(
          body.username,
          body.password,
          body.email,
         'user'
        )
        res.status(200).send({
          success:true,
          data:result
        })
      } catch (error) {
        next(error);
      }
})

router.post('/login', async function(req, res, next) {
    try {
        let username = req.body.username;
        let password = req.body.password;
        let result = await userController.checkLogin(username,password);
        res.status(200).send({
            success:true,
            data:result
        })
      } catch (error) {
        next(error);
      }
})

router.get('/me', check_authentication, async function(req, res, next){
    try {
      res.status(200).send({
        success:true,
        data:req.user
    })
    } catch (error) {
        next();
    }
})

// Reset password (chỉ admin thực hiện được)
router.get('/resetPassword/:id', check_authentication, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).send({ message: 'Access denied' });
        }
        const { id } = req.params;
        const hashedPassword = await bcrypt.hash('123456', 10);
        
        let result = await userController.updateUserPassword(id, hashedPassword);
        res.status(200).send({ message: 'Password has been reset to 123456', data: result });
    } catch (error) {
        res.status(500).send({ message: 'Error resetting password', error });
    }
});

// Change password
router.post('/changePassword', check_authentication, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        let user = await userController.getUserById(req.user.id);
        
        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }
        
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: 'Current password is incorrect' });
        }
        
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        let result = await userController.updateUserPassword(req.user.id, hashedNewPassword);
        
        res.status(200).send({ message: 'Password changed successfully', data: result });
    } catch (error) {
        res.status(500).send({ message: 'Error changing password', error });
    }
});

module.exports = router;
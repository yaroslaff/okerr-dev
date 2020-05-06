import datetime
import hashlib

class VerificationCode():
    secret = 'aslxz82jbziz8xca))-fnzxc24m/3*(vlkvyo87yzhlasldjhajklsdf' 
    
    def get_code(self, email, purpose='', datecode=None):
        if datecode is None:
            datecode = datetime.datetime.now().strftime('%Y%m%d')
        text = ':'.join([datecode, email, purpose, self.secret])
        h = hashlib.sha256(text.encode('utf8')).hexdigest()
        return (datecode, h)

    def verify_code(self, datecode, email, purpose, usercode):
        dt = datetime.datetime.strptime(datecode, '%Y%m%d')
        tdlim = datetime.timedelta(days=2)
        td = datetime.datetime.now() - dt
        if td > tdlim:
            raise ValueError('Verification code expired')
        
        code = self.get_code(email,purpose,datecode)[1]
        if code != usercode:
            raise ValueError('Verification code mismatch')
        
        return True
        
if __name__ == '__main__':
    addr = 'test@test.com'
    purpose = 'zzzz'

    vc = VerificationCode()    
    dcode, code = vc.get_code(addr, purpose)
    
    if vc.verify_code(dcode, addr, purpose, code):
        print("verify good")
    

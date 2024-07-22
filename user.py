import rabin 

class user:

    def __init__(self,name):
        self.p, self.q = rabin.generate_keys()
        self.rabin_public = self.p * self.q
        self.name = name
        self.private_key = None
        self.point = None
        self.salsa_key = None
        self.iv = None
        self.plainText = None

    def set_pKey(self,pkey):
        self.private_key = pkey
    def set_point(self,point):
        self.point = point
    def set_iv(self,iv):
        self.iv = iv
    def set_salsa_key(self,salsa_key):
        self.salsa_key = salsa_key
    def set_plainText(self,plainText):
        self.plainText = plainText
class user:

    def __init__(self,name):
        self.name = name
        self.private_key = None
        self.point = None
        self.salsa_key = None
        self.iv = None


    def set_pKey(self,pkey):
        self.private_key = pkey

    def set_point(self,point):
        self.point = point
    def set_iv(self,iv):
        self.iv = iv
    def set_salsa_key(self,salsa_key):
        self.salsa_key = salsa_key
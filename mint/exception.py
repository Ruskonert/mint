class MintExecuteParamError(Exception):
    opt = ''
    msg = ''
    def __init__(self, msg, opt=''):
        self.msg = msg
        self.opt = opt
        Exception.__init__(self, msg, opt)

    def __str__(self):
        return self.msg
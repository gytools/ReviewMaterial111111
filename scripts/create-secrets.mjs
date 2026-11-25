import {mkdirSync,writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
mkdirSync(new URL('../private/',import.meta.url),{recursive:true,mode:0o700});
const path=new URL('../private/secrets.json',import.meta.url);
try {
 writeFileSync(path,JSON.stringify({APP_SECRET:randomBytes(48).toString('hex'),SETUP_TOKEN:randomBytes(32).toString('hex')},null,2)+'\n',{flag:'wx',mode:0o600});
 console.log('已生成 private/secrets.json。部署时使用此文件；初始化口令是其中的 SETUP_TOKEN。请保管此文件，不要上传 GitHub 或发送给学生。');
} catch(e) {
 if(e.code==='EEXIST')console.log('private/secrets.json 已存在，已保留原密钥。');
 else throw e;
}

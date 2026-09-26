// Passe un secret au serveur du service par SSH, sur l'entrée standard : il n'est jamais écrit sur cet ordinateur.
// VIGIRIB_SERVEUR : alias SSH du compte du service (défaut « vigi »).
import {spawn} from 'node:child_process';

export const slug=s=>String(s||'client').normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||'client';

export function surLeServeur(commande,entree,{serveur=process.env.VIGIRIB_SERVEUR||'vigi',executer=spawn}={}){
  return new Promise((ok,ko)=>{
    const p=executer('ssh',[serveur,commande],{stdio:['pipe','inherit','inherit']});
    p.on('error',ko);
    p.on('close',code=>code===0?ok():ko(Error(`le serveur a refusé (code ${code})`)));
    p.stdin.end(entree);
  });
}

// Dépose ~/.vigi/clients/<nom>.env (0600) sur le serveur, sans jamais écraser un fichier existant.
export function deposerClient(nom,contenu,options){
  if(!/^[a-z0-9-]+$/.test(nom))throw Error('Nom de client invalide.');
  const f=`~/.vigi/clients/${nom}.env`;
  return surLeServeur(`umask 077; mkdir -p ~/.vigi/clients; if [ -e ${f} ]; then echo "${f} existe déjà : rien n’est écrasé." >&2; exit 3; fi; cat > ${f}`,contenu,options);
}

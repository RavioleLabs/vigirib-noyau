// Texte d'un PDF, sans dépendance : suffisant pour y trouver un IBAN, pas pour mettre en page.
// Lit les flux de contenu (compressés FlateDecode ou non), les chaînes des opérateurs Tj / TJ / ' / ",
// et applique les tables ToUnicode quand la police en a (polices CID des générateurs de factures).
// Un PDF scanné (image) ne contient pas de texte : il faudrait de l'OCR, hors périmètre.
import {inflateSync} from 'node:zlib';

function flux(octets){
  const s=octets.toString('latin1'),out=[];
  const re=/<<((?:(?!<<)[\s\S])*?)>>\s*stream\r?\n/g;let m;
  while((m=re.exec(s))){
    const debut=m.index+m[0].length,fin=s.indexOf('endstream',debut);
    if(fin<0)break;
    let brut=octets.subarray(debut,fin);
    if(/FlateDecode/.test(m[1])){try{brut=inflateSync(brut);}catch{try{brut=inflateSync(brut.subarray(0,brut.length-1));}catch{continue;}}}
    else if(/\/Filter/.test(m[1]))continue;
    out.push(brut.toString('latin1'));
    re.lastIndex=fin;
  }
  return out;
}

// Tables ToUnicode : code hexadécimal vers texte (bfchar et bfrange).
function tables(flots){
  const t=new Map();
  const hex=h=>Buffer.from(h.length%4?h.padStart(Math.ceil(h.length/4)*4,'0'):h,'hex').swap16().toString('utf16le');
  for(const f of flots){
    if(!/begincmap/.test(f))continue;
    for(const b of f.matchAll(/beginbfchar([\s\S]*?)endbfchar/g))
      for(const [,src,dst] of b[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g))t.set(src.toUpperCase(),hex(dst));
    for(const b of f.matchAll(/beginbfrange([\s\S]*?)endbfrange/g))
      for(const [,a,z,dst] of b[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)){
        const lo=parseInt(a,16),hi=parseInt(z,16),base=parseInt(dst,16);
        for(let c=lo;c<=hi&&c-lo<65536;c++)t.set(c.toString(16).toUpperCase().padStart(a.length,'0'),String.fromCodePoint(base+c-lo));
      }
  }
  return t;
}

function chaineLitterale(s){
  return s.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g,(_,e)=>({n:'\n',r:'\r',t:'\t',b:'\b',f:'\f','(':'(',')':')','\\':'\\'})[e]??String.fromCharCode(parseInt(e,8)));
}

function chaineHex(h,t){
  h=h.replace(/\s/g,'').toUpperCase();
  if(t.size){
    const l=[...t.keys()][0].length;
    let out='';for(let i=0;i<h.length;i+=l)out+=t.get(h.slice(i,i+l))??'';
    if(out)return out;
  }
  return Buffer.from(h.length%2?h+'0':h,'hex').toString('latin1');
}

export function textePdf(octets){
  if(!Buffer.isBuffer(octets))octets=Buffer.from(octets);
  if(octets.subarray(0,5).toString()!=='%PDF-')return '';
  const flots=flux(octets),t=tables(flots),lignes=[];
  // Factur-X : la facture structurée (XML CII) est un fichier incorporé au PDF. On en garde le texte des champs.
  for(const f of flots)if(/<\?xml|CrossIndustryInvoice|<(\w+:)?Invoice\b/.test(f.slice(0,4000)))lignes.push(f.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim());
  for(const f of flots){
    if(!/\b(Tj|TJ|BT)\b/.test(f))continue;
    for(const bloc of f.matchAll(/BT([\s\S]*?)ET/g)){
      let ligne='';
      // Chaînes littérales (avec parenthèses échappées) ou hexadécimales, dans l'ordre d'apparition.
      for(const m of bloc[1].matchAll(/\(((?:\\.|[^\\)])*)\)|<([0-9A-Fa-f\s]+)>|(T\*|Td|TD|Tm|')/g)){
        if(m[3]){ligne+=' ';continue;}
        ligne+=m[1]!==undefined?chaineLitterale(m[1]):chaineHex(m[2],t);
      }
      lignes.push(ligne.replace(/\s+/g,' ').trim());
    }
  }
  return lignes.filter(Boolean).join('\n');
}

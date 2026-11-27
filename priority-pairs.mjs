export function resolvePriorityPairs(order,pairs=[],actualStatus={}) {
 const resolved=Object.fromEntries(Object.entries(order).map(([role,ids])=>[role,[...ids]]));
 const seen=new Set();
 for(const pair of pairs){if(!Array.isArray(pair)||pair.length!==2)continue;const [a,b]=pair;if(a===b||seen.has(a)||seen.has(b))continue;
 const role=Object.keys(resolved).find(k=>resolved[k].includes(a)&&resolved[k].includes(b));if(!role)continue;seen.add(a);seen.add(b);
 const list=resolved[role],i=list.indexOf(a),j=list.indexOf(b),lo=Math.min(i,j),hi=Math.max(i,j);
 const get=id=>actualStatus instanceof Map?actualStatus.get(id):actualStatus[id];
 if(get(list[lo])!=="T"&&get(list[hi])==="T")[list[lo],list[hi]]=[list[hi],list[lo]];
 }
 return resolved;
}

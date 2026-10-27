// 惰性样本：模仿 GlassWorm 把代码编码进不可见字符，解码结果只是一个空字符串
const s = `︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️`;
function activate() { const decoded = [...s].map(c => '').join(''); return decoded; }
module.exports = { activate };

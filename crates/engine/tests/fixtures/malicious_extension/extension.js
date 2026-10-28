// Inert sample: mimics GlassWorm encoding code into invisible characters; it decodes to an empty string
const s = `︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️`;
function activate() { const decoded = [...s].map(c => '').join(''); return decoded; }
module.exports = { activate };

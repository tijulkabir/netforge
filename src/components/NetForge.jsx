import React, { useState, useEffect } from 'react';
import './NetForge.css';
import { Terminal, Play, X, GripVertical, Search, ChevronRight, ChevronDown } from 'lucide-react';
import { operations, categories, runRecipe } from '../core/operations';

const NetForge = () => {
    const [input, setInput] = useState('');
    const [output, setOutput] = useState('');
    const [recipe, setRecipe] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [expandedCats, setExpandedCats] = useState({});

    useEffect(() => {
        const result = runRecipe(input, recipe);
        setOutput(result);
    }, [input, recipe]);

    const addOperation = (opName) => {
        setRecipe([...recipe, opName]);
    };

    const removeOperation = (index) => {
        const newRecipe = [...recipe];
        newRecipe.splice(index, 1);
        setRecipe(newRecipe);
    };

    const toggleCat = (cat) => {
        setExpandedCats(prev => ({ ...prev, [cat]: !prev[cat] }));
    };

    const getFilteredCategories = () => {
        if (!searchTerm) return categories;
        const filtered = {};
        Object.keys(categories).forEach(cat => {
            const matches = categories[cat].filter(op =>
                op.name.toLowerCase().includes(searchTerm.toLowerCase())
            );
            if (matches.length > 0) {
                filtered[cat] = matches;
            }
        });
        return filtered;
    };

    const displayCats = getFilteredCategories();

    useEffect(() => {
        if (searchTerm) {
            const allOpen = {};
            Object.keys(categories).forEach(k => allOpen[k] = true);
            setExpandedCats(allOpen);
        }
    }, [searchTerm]);

    return (
        <div className="forge-container">
            <header className="forge-header">
                <div className="logo-area">
                    <Terminal size={24} color="#00ff41" />
                    <span>NETFORGE <span className="version">v2.0</span></span>
                </div>
                <div className="header-controls">
                    <button className="run-btn" onClick={() => setOutput(runRecipe(input, recipe))}>
                        <Play size={16} /> BAKE
                    </button>
                </div>
            </header>

            <div className="forge-workspace">
                <aside className="tool-sidebar">
                    <div className="panel-header">OPERATIONS</div>
                    <div className="search-box">
                        <Search size={14} className="search-icon" />
                        <input
                            type="text"
                            placeholder="Search..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <div className="tool-list">
                        {Object.keys(displayCats).map(cat => (
                            <div key={cat} className="category-group">
                                <div className="category-header" onClick={() => toggleCat(cat)}>
                                    {expandedCats[cat] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                                    <span>{cat}</span>
                                </div>
                                {expandedCats[cat] && (
                                    <div className="category-items">
                                        {displayCats[cat].map(op => (
                                            <div key={op.name} className="tool-item" onClick={() => addOperation(op.name)}>
                                                {op.name}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </aside>

                <main className="recipe-area">
                    <div className="panel-header">RECIPE</div>
                    <div className="recipe-list">
                        {recipe.length === 0 && (
                            <div className="recipe-placeholder">
                                <div style={{ opacity: 0.5 }}>No operations selected</div>
                                <div style={{ fontSize: '0.8rem', marginTop: '10px', color: '#666' }}>
                                    Browse categories or search to add tools.
                                </div>
                            </div>
                        )}
                        {recipe.map((op, idx) => (
                            <div key={idx} className="recipe-item">
                                <GripVertical size={14} className="drag-handle" />
                                <span className="recipe-name">{op}</span>
                                <button className="remove-btn" onClick={() => removeOperation(idx)}>
                                    <X size={14} />
                                </button>
                            </div>
                        ))}
                    </div>
                </main>

                <section className="io-area">
                    <div className="io-panel input-panel">
                        <div className="panel-header">INPUT</div>
                        <textarea
                            placeholder="Paste data here..."
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                        ></textarea>
                        <div className="io-footer">Length: {input.length}</div>
                    </div>
                    <div className="io-panel output-panel">
                        <div className="panel-header">OUTPUT</div>
                        <textarea readOnly placeholder="Result..." value={output}></textarea>
                        <div className="io-footer">Length: {output.length}</div>
                    </div>
                </section>
            </div>
        </div>
    );
};

export default NetForge;

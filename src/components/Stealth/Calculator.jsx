import React, { useState } from 'react';
import './Calculator.css';

const Calculator = ({ onUnlock }) => {
  const [display, setDisplay] = useState('0');
  const [equation, setEquation] = useState('');

  const handlePress = (val) => {
    if (val === 'C') {
      setDisplay('0');
      setEquation('');
      return;
    }

    if (val === '=') {
      // Trigger Logic
      if (display === '1971-2024' || equation === '1971-2024') {
        onUnlock();
        return;
      }
      try {
        // eslint-disable-next-line no-eval
        const result = eval(display);
        setDisplay(String(result));
        setEquation('');
      } catch (e) {
        setDisplay('Error');
      }
      return;
    }

    if (display === '0' || display === 'Error') {
      setDisplay(val);
    } else {
      setDisplay(display + val);
    }
    setEquation(equation + val);
  };

  const buttons = [
    'C', '(', ')', '/',
    '7', '8', '9', '*',
    '4', '5', '6', '-',
    '1', '2', '3', '+',
    '0', '.', '=',
  ];

  return (
    <div className="calc-container">
      <div className="calc-display">{display}</div>
      <div className="calc-grid">
        {buttons.map((btn) => (
          <button 
            key={btn} 
            className={`calc-btn ${['C', '=', '+', '-', '*', '/'].includes(btn) ? 'accent' : ''}`}
            onClick={() => handlePress(btn)}
          >
            {btn}
          </button>
        ))}
      </div>
    </div>
  );
};

export default Calculator;

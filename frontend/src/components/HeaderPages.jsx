import React from 'react'
import Header from './Header.jsx';

function HeaderPages({children}) {
    return (
    <div>
        <Header/>
        {children}
    </div>
    )
}

export default HeaderPages

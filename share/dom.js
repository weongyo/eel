/*-
 * Copyright (c) 2013 Weongyo Jeong <weongyo@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

function __extend__(a, b) {
    for (var i in b) {
        var g = b.__lookupGetter__(i);
	var s = b.__lookupSetter__(i);
        if (g || s) {
            if (g)
		a.__defineGetter__(i, g);
            if (s)
		a.__defineSetter__(i, s);
        } else
            a[i] = b[i];
    }
    return a;
}

function __setArray__( target, array ) {
    target.length = 0;
    Array.prototype.push.apply(target, array);
}

/*----------------------------------------------------------------------*/

DOMImplementation = function() {
    this.preserveWhiteSpace = false;
    this.namespaceAware = true;
    this.errorChecking  = true;
};

/*----------------------------------------------------------------------*/

var __appendChild__ = function(nodelist, newChild) {
    if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE)
        Array.prototype.push.apply(nodelist, newChild.childNodes.toArray());
    else
        Array.prototype.push.apply(nodelist, [newChild]);
};

var __isAncestor__ = function(target, node) {
    return ((target == node) ||
	    ((target.parentNode) && (__isAncestor__(target.parentNode, node))));
};

var __ownerDocument__ = function(node) {
    return (node.nodeType == Node.DOCUMENT_NODE) ? node : node.ownerDocument;
};

Node = function(ownerDocument) {
    this.ownerDocument = ownerDocument;
    this.childNodes = new NodeList(ownerDocument, this);
};
Node.ELEMENT_NODE                = 1;
Node.ATTRIBUTE_NODE              = 2;
Node.TEXT_NODE                   = 3;
Node.CDATA_SECTION_NODE          = 4;
Node.ENTITY_REFERENCE_NODE       = 5;
Node.ENTITY_NODE                 = 6;
Node.PROCESSING_INSTRUCTION_NODE = 7;
Node.COMMENT_NODE                = 8;
Node.DOCUMENT_NODE               = 9;
Node.DOCUMENT_TYPE_NODE          = 10;
Node.DOCUMENT_FRAGMENT_NODE      = 11;
Node.NOTATION_NODE               = 12;
Node.NAMESPACE_NODE              = 13;

Node.DOCUMENT_POSITION_EQUAL        = 0x00;
Node.DOCUMENT_POSITION_DISCONNECTED = 0x01;
Node.DOCUMENT_POSITION_PRECEDING    = 0x02;
Node.DOCUMENT_POSITION_FOLLOWING    = 0x04;
Node.DOCUMENT_POSITION_CONTAINS     = 0x08;
Node.DOCUMENT_POSITION_CONTAINED_BY = 0x10;
Node.DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC      = 0x20;
__extend__(Node.prototype, {
    appendChild : function(newChild) {
        if (!newChild)
            return null;
        if (__ownerDocument__(this).implementation.errorChecking) {
            if (this._readonly) {
                throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
            }
            if (__ownerDocument__(this) != __ownerDocument__(this)) {
                throw(new DOMException(DOMException.WRONG_DOCUMENT_ERR));
            }
            if (__isAncestor__(this, newChild)) {
              throw(new DOMException(DOMException.HIERARCHY_REQUEST_ERR));
            }
        }
        var newChildParent = newChild.parentNode;
        if (newChildParent) {
            newChildParent.removeChild(newChild);
        }
        __appendChild__(this.childNodes, newChild);

        if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE) {
            if (newChild.childNodes.length > 0) {
                for (var ind = 0; ind < newChild.childNodes.length; ind++) {
                    newChild.childNodes[ind].parentNode = this;
                }

                if (this.lastChild) {
                    this.lastChild.nextSibling = newChild.childNodes[0];
                    newChild.childNodes[0].previousSibling = this.lastChild;
                    this.lastChild = newChild.childNodes[newChild.childNodes.length-1];
                } else {
                    this.lastChild = newChild.childNodes[newChild.childNodes.length-1];
                    this.firstChild = newChild.childNodes[0];
                }
            }
        } else {
            newChild.parentNode = this;
            if (this.lastChild) {
                this.lastChild.nextSibling = newChild;
                newChild.previousSibling = this.lastChild;
                this.lastChild = newChild;
            } else {
                this.lastChild = newChild;
                this.firstChild = newChild;
            }
       }
       return newChild;
    },
});

/*----------------------------------------------------------------------*/

NodeList = function(ownerDocument, parentNode) {
    this.length = 0;
    this.parentNode = parentNode;
    this.ownerDocument = ownerDocument;
    this._readonly = false;
    __setArray__(this, []);
};

/*----------------------------------------------------------------------*/

Document = function(implementation, docParentWindow) {
    Node.apply(this, arguments);
    this.implementation = implementation;
    this.ownerDocument = null;
};
Document.prototype = new Node();
__extend__(Document.prototype, {
    get documentElement(){
        var i, length = this.childNodes ? this.childNodes.length : 0;

        for (i = 0; i < length; i++) {
            if (this.childNodes[i].nodeType === Node.ELEMENT_NODE)
                return this.childNodes[i];
        }
        return null;
    },
    get nodeType(){
        return Node.DOCUMENT_NODE;
    },
});

/*----------------------------------------------------------------------*/

Element = function(ownerDocument) {
    Node.apply(this, arguments);
};
Element.prototype = new Node();

/*----------------------------------------------------------------------*/

var  __DOMElement__ = Element;

HTMLElement = function(ownerDocument) {
    __DOMElement__.apply(this, arguments);
};
HTMLElement.prototype = new Element();

/*----------------------------------------------------------------------*/

HTMLHeadElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLHeadElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLHtmlElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};

HTMLHtmlElement.prototype = new HTMLElement();
__extend__(HTMLHtmlElement.prototype, {
    toString: function() {
        return '[object HTMLHtmlElement]';
    }
});

/*----------------------------------------------------------------------*/

HTMLDocument = function(implementation, ownerWindow, referrer) {
    Document.apply(this, arguments);
};
HTMLDocument.prototype = new Document();
__extend__(HTMLDocument.prototype, {
    createElement: function(tagName) {
        var node;

        tagName = tagName.toUpperCase();
	switch (tagName) {
        case "HEAD":
            node = new HTMLHeadElement(this);
	    break;
	case "HTML":
	    node = new HTMLHtmlElement(this);
	    break;
	default:
	    DUMP(tagName);
	}
	node.nodeName  = tagName;
        return (node);
    },
    get documentElement() {
        var html = Document.prototype.__lookupGetter__('documentElement').apply(this,[]);
        if( html === null){
            html = this.createElement('html');
            this.appendChild(html);
	    DUMP(html);
            html.appendChild(this.createElement('head'));
            html.appendChild(this.createElement('body'));
        }
        return (html);
    },
});

/*----------------------------------------------------------------------*/

Window = function(scope, parent, opener) {
    scope.__defineGetter__('window', function () {
        return scope;
    });
    var $htmlImplementation = new DOMImplementation();
    var $document = new HTMLDocument($htmlImplementation, scope);
    return __extend__(scope, {
        get document(){
            return $document;
        },
        set document(doc){
            $document = doc;
        },
        get window(){
            return this;
        },
     });
};

new Window(this, this);



import * as React from "react";
import { Container, Form, Col, Button } from "react-bootstrap";
import logo from '../../assets/logo.svg';
import history from '../../lib/history';
import { isMobile, isAndroid, isIOS } from 'react-device-detect'
import { getHeaders } from '../../lib/auth'

interface NewProps {
    match: any
}

interface NewState {
    isAuthenticated?: Boolean
    remove: any
    currentContainer: any
    token?: string
    user?: any
    isValid: Boolean
}

class Remove extends React.Component<NewProps, NewState> {

    constructor(props: NewProps) {
        super(props);

        this.state = {
            currentContainer: '',
            isValid: false,
            remove: {
                email: ''
            }
        };
    }

    componentDidMount() {
        this.setState({currentContainer: this.privacyContainer()});
        if (isMobile) {
            if (isAndroid) {
                window.location.href = "https://play.google.com/store/apps/details?id=com.internxt.cloud";
            } else if (isIOS) {
                window.location.href = "https://itunes.apple.com/us/app/x-cloud-secure-file-storage/id1465869889";
            }
        }

        const xUser = JSON.parse(localStorage.getItem('xUser') || '{}');
        const xToken = localStorage.getItem('xToken');
        const mnemonic = localStorage.getItem('xMnemonic');
        const haveInfo = (xUser && xToken && mnemonic);

        if (this.state.isAuthenticated === true || haveInfo) {
            history.push('/app')
        }
    }

    handleChangeRemove = (event: any) => {
        var removeState = this.state.remove;
        removeState[event.target.id] = event.target.value;

        this.setState({ remove: removeState });
    }

    validateEmail = (email: string) => {
        var re = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
        return re.test(String(email).toLowerCase());
    }

    validateForm = () => {
        let isValid = true;
        if (this.state.remove.email === '' || this.state.remove.email.length < 5 || !this.validateEmail(this.state.remove.email)) isValid = false;
        return isValid;
    }

    sendDeactivationEmail = (email: string) => {
        fetch(`/api/reset/${email}`, {
            method: 'GET',
            headers: getHeaders(false, false)
        })
            .then(res => res.json())
            .then(res => {
                this.setState({ currentContainer: this.deActivationContainer() });        
            });
    }

    privacyContainer() {
        const isValid = this.validateForm();
        return (<div className="container-register">
            <p className="container-title">X Cloud Security</p>
            <p className="privacy-disclaimer">As specified during the sign up process, X Cloud encrypts your files, and only you have access to those. We never know your password, and thus, that way, only you can decrypt your account. For that reason, if you forget your password, we can't restore your account. What we can do, however, is to delete your account and erase all its files, so that you can sign up again. Please enter your email below so that we can process the account removal.</p>

            <Form>
                <Form.Row style={{ paddingTop: '20px' }}>
                    <Form.Group as={Col} controlId="email">
                        <Form.Control placeholder="Email address" type="email" required autoComplete="off" onChange={this.handleChangeRemove} onBlur={() => {
                            if (this.state.isValid !== this.validateForm()) {
                                this.setState({ isValid: this.validateForm() });
                                this.setState({ currentContainer: this.privacyContainer() });
                            }
                        }}/>
                    </Form.Group>
                </Form.Row>

                <Form.Row className="form-register-submit">
                    <Form.Group as={Col}>
                        <button className="btn-block off" onClick={e => {
                            history.push('/login');
                            e.preventDefault();
                        }}>Back</button>
                    </Form.Group>

                    <Form.Group as={Col}>
                        <Button className="on btn-block" disabled={!isValid} onClick={e => {
                            e.preventDefault();
                            this.sendDeactivationEmail(this.state.remove.email);
                        }}>Continue</Button>
                    </Form.Group>
                </Form.Row>
            </Form>
        </div>);
    }

    deActivationContainer() {
        return (<div className="container-register">
            <p className="container-title">Deactivation Email</p>
            <p className="privacy-disclaimer">Please check your email and follow the instructions to deactivate your account so you can start using X Cloud again.</p>
            <div className="privacy-remainders" style={{ paddingTop: '20px' }}>Once you deactivate your account, you will be able to sign up using the same email address. Please store your password somewhere safe. With X Cloud, only you are the true owner of your files on the cloud. With great power there must also come great responsibility.</div>
            <button className="btn-block on" onClick={e => {
                e.preventDefault();
                this.sendDeactivationEmail(this.state.remove.email);
            }}>Re-send deactivation email</button>
        </div>);
    }

    render() {
        return (<div className="login-main">
            <Container className="login-container-box">
                <p className="logo"><img src={logo} alt="Logo" /></p>
                {this.state.currentContainer}
            </Container>
        </div>
        );
    }
}

export default Remove;
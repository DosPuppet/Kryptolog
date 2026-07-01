import { useMessengerContext } from '../context/MessengerContext';

export function useMessenger() {
    return useMessengerContext();
}

const { createOAuthAppAuth } = require('@octokit/auth-oauth-app'); // eslint-disable-line @typescript-eslint/no-var-requires
const cors = require('cors')({ origin: true }); // eslint-disable-line @typescript-eslint/no-var-requires
import { FieldValue, v1 } from '@google-cloud/firestore';
import * as functions from 'firebase-functions';
import { StatusCodes } from 'http-status-codes';
import fetch from 'node-fetch';

import { NOTIFICATION_TYPES } from 'Shared/notifications/consts';
import { discoverAndGenerateDocs, discoverDocs, generateDocs, sgdOnGeneratedDocSavedHandler } from './generated-docs';
import { DocumentMetadata, isDocumentId, isDocumentMetadata } from './generated-docs/documents/document';
import { RepoTarget, isRepoTarget } from './generated-docs/utils/clone';
import { sendSGMail } from './utils/sendgrid';
import { logEventCloud } from './eventLogger/logAndReportEvent';
import * as commonUtils from './utils/common';
import { firestoreCollectionNames, resourcesErrors } from './utils/consts';
import { checkIfRepoExistsAndUserInRepo } from './utils/check_helpers';
import { getLogger } from './utils/cloud-logger';
import { isProduction, isStage, projectId } from './utils/config';

import { githubApp, marketplaceGitHubAppHandler } from './githubApp';
import { dailyMailHandler } from './mailer';
import { newDoc } from './mailer/newDoc';
import {
    fetchBillingConfig,
    fetchSubscriptionData,
    subscribeWorkspaceToProPlan,
    updateSubscriptionQuantity,
    updateWorkspaceBilling,
} from './billing';
import { billingPlanTypes } from './billing/constants';
import * as compassFunctions from './compass';
import * as trackingFunctions from './tracking';
import * as salesforceFunctions from './salesforce';
import * as repoFunctions from './repoFunctions';
import * as sayThanksFunctions from './doc-functions/contributors';
import * as slackFunctions from './slack';
import * as slackUtils from './slack/slack-utils';

import {
    reportedFirestoreFunction,
    reportedHttpCallFunction,
    reportedHttpRequestFunction,
    reportedScheduledFunction,
    reportedTopicFunction,
} from './utils/reporting';

const client = new v1.FirestoreAdminClient();

const db = commonUtils.initializedDB;
const admin = commonUtils.initializedAdmin;

const DEFAULT_WORKSPACE_USERS_LIMIT = 15;
const DEFAULT_PRIVATE_REPO_LIMIT = 1;

function getWebUrlHost() {
    return isProduction
        ? 'https://app.swimm.io'
        : isStage
            ? 'https://swimm-stag.web.app'
            : 'https://swimm-web-app.web.app';
}

async function getUsersEmails(uids) {
    if (!uids || uids.length === 0) {
        return [];
    }
    const uidsList = uids.map((uid) => {
        return { uid };
    });
    const users = await admin.auth().getUsers(uidsList);
    const emails = users.users.map((user) => user.email);
    return emails;
}

export const sayDocThanks = sayThanksFunctions.sayDocThanks;
export const addUserProperties = trackingFunctions.addUserProperties;
export const addAccountProperties = trackingFunctions.addAccountProperties;
export const groupEvent = trackingFunctions.groupEvent;
export const trackEvent = trackingFunctions.trackEvent;
export const updateLoginInSalesforce = salesforceFunctions.updateLoginInSalesforce;
export const updateSignupInSalesforce = salesforceFunctions.updateSignupInSalesforce;
export const updateWorkspaceInSalesforce = salesforceFunctions.updateWorkspaceInSalesforce;
export const updateWorkspaceUserInSalesforce = salesforceFunctions.updateWorkspaceUserInSalesforce;
export const updateRepoInSalesforce = salesforceFunctions.updateRepoInSalesforce;
export const sendCRMForm = salesforceFunctions.sendCRMForm;
export const compassResolveRepo = compassFunctions.compassResolveRepo;
export const compassSetTrigger = compassFunctions.compassSetTrigger;
export const setIsRepoPrivate = repoFunctions.setIsRepoPrivate;
export const slackAuth = slackFunctions.slackAuth;
export const changeSlackChannelToNotify = slackUtils.changeSlackChannelToNotify;
export const getSlackChannelList = slackUtils.getSlackChannelList;

interface SGDRepoProperties {
    [branch: string]: {
        numberOfDocuments: number;
    };
}

function setSGDObjectOnRepo(repoId: string, sgdObject: SGDRepoProperties) {
    const updateObject = {};
    for (const [branchName, properties] of Object.entries(sgdObject)) {
        updateObject[`sgdProperties.${branchName}`] = { ...properties, lastUpdated: admin.database.ServerValue.TIMESTAMP };
    }
    db.collection(firestoreCollectionNames.REPOSITORIES).doc(repoId).set(updateObject, { merge: true });
}

function isSGDRequestData(obj: unknown): obj is SGDRequestData {
    const isObj = typeof obj === 'object';
    if (!isObj) {
        return false;
    }
    const action = obj['action'];
    if (typeof action !== 'string' || !Object.values(SGDAction).includes(action as SGDAction)) {
        const message = `Unknown action: ${action}`;
        throw { message, code: StatusCodes.NOT_FOUND };
    }
    const repoId = obj['repoId'];
    if (typeof repoId !== 'string' || repoId.length === 0) {
        const message = `Incorrect repoId: ${repoId}`;
        throw { message, code: StatusCodes.NOT_FOUND };
    }
    const repoTarget: unknown = obj['repoTarget'];
    const cloneToken: unknown = obj['cloneToken'];
    try {
        if (!isRepoTarget(repoTarget)) {
            throw TypeError(`Incorrect repoTarget type: ${JSON.stringify(repoTarget)}`);
        }
        if (typeof cloneToken !== 'string') {
            throw TypeError(`Incorrect cloneToken: ${typeof cloneToken}`);
        }
    } catch (error: unknown) {
        const message = `Request data incorrect: ${error.toString()}`;
        throw { message, code: StatusCodes.BAD_REQUEST };
    }
    return true;
}

function isGenerateData(obj: SGDRequestData): obj is SGDGenerateData {
    const documentMetadatas: unknown = obj['documentMetadatas'];
    try {
        if (!Array.isArray(documentMetadatas) || !documentMetadatas.every(isDocumentMetadata)) {
            throw TypeError(`Incorrect documentMetadatas: ${documentMetadatas}`);
        }
    } catch (error: unknown) {
        const message = `Request data incorrect: ${error.toString()}`;
        throw { message, code: StatusCodes.BAD_REQUEST };
    }
    return true;
}

function isDiscoverAndGenerateData(obj: SGDRequestData): obj is SGDDiscoverAndGenerate {
    const ignoreDocumentIds: unknown = obj['ignoreDocumentIds'];
    const fromDocumentIndex: unknown = obj['fromDocumentIndex'];
    const toDocumentIndex: unknown = obj['toDocumentIndex'];
    try {
        if (!Array.isArray(ignoreDocumentIds) || !ignoreDocumentIds.every(isDocumentId)) {
            throw TypeError(`Incorrect ignoreDocumentIds: ${ignoreDocumentIds}`);
        }
        if (fromDocumentIndex !== undefined && typeof fromDocumentIndex !== 'number') {
            throw TypeError(
                `Incorrect fromDocumentIndex: value '${fromDocumentIndex}' from type '${typeof fromDocumentIndex}'`
            );
        }
        if (toDocumentIndex !== undefined && typeof toDocumentIndex !== 'number') {
            throw TypeError(`Incorrect fromDocumentIndex: value '${toDocumentIndex}' from type '${typeof toDocumentIndex}'`);
        }
    } catch (error: unknown) {
        const message = `Request data incorrect: ${error.toString()}`;
        throw { message, code: StatusCodes.BAD_REQUEST };
    }
    return true;
}

enum SGDAction {
    DISCOVER = 'discover',
        GENERATE = 'generate',
        DISCOVER_AND_GENERATE = 'discover-and-generate',
}

interface SGDRequestData {
    action: SGDAction;
    repoTarget: RepoTarget;
    cloneToken: string;
    repoId: string;
}

interface SGDGenerateData extends SGDRequestData {
    documentMetadatas: DocumentMetadata[];
}

interface SGDDiscoverAndGenerate extends SGDRequestData {
    ignoreDocumentIds: string[];
    fromDocumentIndex: number;
    toDocumentIndex: number;
}

// We don't want to return 100 documents as it will be confusing for the user and they will not be too valuable.
const MAX_DOCUMENTS_TO_RETURN = 50;

const MAX_FIREBASE_FUNCTION_TIMEOUT_SECONDS = 540;

// We have only one cloud function so that we can cache the cloned repository between different kinds of SGD
// invocations (See https://firebase.google.com/docs/functions/tips#use_global_variables_to_reuse_objects_in_future_invocations).
export const sgd = functions
    .runWith({
        timeoutSeconds: MAX_FIREBASE_FUNCTION_TIMEOUT_SECONDS,
        // Note that setting this lower will give us less CPU resources, so we have to keep this high (also, we need a lot
        // of RAM for cloning the repo and all the analyses).
        memory: '8GB',
    })
    .https.onCall(
        reportedHttpCallFunction(
            { name: 'sgd', excludeFieldsFromEntryLog: ['cloneToken', 'documentMetadatas'] },
            async (logger, data, context) => {
                if (!context.auth) {
                    logger.error('SGD failed, user is unauthenticated');
                    return { status: 'error', code: StatusCodes.UNAUTHORIZED };
                }
                try {
                    if (!isSGDRequestData(data)) {
                        throw { message: `Invalid data`, code: StatusCodes.BAD_REQUEST };
                    }
                    await checkIfRepoExistsAndUserInRepo(data.repoId, context.auth.uid);
                } catch (checkFailedState) {
                    logger.error(`SGD failed: ${checkFailedState.message}`, { repoId: data?.repoId });
                    return { status: 'error', code: checkFailedState.code };
                }
                switch (data.action) {
                    case SGDAction.DISCOVER:
                        return sgdDiscover(logger, data);
                    case SGDAction.GENERATE:
                        return sgdGenerate(logger, data);
                    case SGDAction.DISCOVER_AND_GENERATE:
                        return sgdDiscoverAndGenerate(logger, data);
                    default:
                        return { status: 'error', code: StatusCodes.NOT_FOUND };
                }
            }
        )
    );

const sgdDiscover = async (logger, data: SGDRequestData) => {
    // Run discovery function
    logger.info('Discovering', { repoId: data.repoId });
    try {
        const discoveredDocs = await discoverDocs(data.repoTarget, data.cloneToken, data.repoId);
        logger.info(
            `Discovered ${discoveredDocs.length} documents - returning the first ${Math.min(
                discoveredDocs.length,
                MAX_DOCUMENTS_TO_RETURN
            )}`,
            { repoId: data.repoId }
        );
        discoveredDocs.splice(MAX_DOCUMENTS_TO_RETURN);
        if (data.repoId) {
            setSGDObjectOnRepo(data.repoId, {
                [data.repoTarget.branchOrTag]: { numberOfDocuments: discoveredDocs.length },
            } as SGDRepoProperties);
        } else {
            logger.info('No repoId provided, not writing SGD properties to DB.');
        }
        return { status: 'success', discoveredDocs };
    } catch (error) {
        logger.error(`SGD discovery failed`, { repoId: data.repoId, error });
        return {
            status: 'error',
            code: StatusCodes.INTERNAL_SERVER_ERROR,
            ...(isProduction ? {} : { error: error.toString() }),
        };
    }
};

const sgdGenerate = async (logger, data: SGDRequestData) => {
    try {
        if (!isGenerateData(data)) {
            throw { message: `Invalid data`, code: StatusCodes.BAD_REQUEST };
        }
    } catch (checkFailedState) {
        logger.error(`SGD generate failed: ${checkFailedState.message}`, { repoId: data?.repoId });
        return { status: 'error', code: checkFailedState.code };
    }

    // Run generation function
    logger.info(`Generating from ${data.documentMetadatas.length} metadata objects`, { repoId: data.repoId });
    try {
        const generatedDocs = await generateDocs(data.repoTarget, data.cloneToken, data.documentMetadatas, data.repoId);
        return { status: 'success', generatedDocs };
    } catch (error) {
        logger.error(`SGD generate failed`, { repoId: data.repoId, error });
        return {
            status: 'error',
            code: StatusCodes.INTERNAL_SERVER_ERROR,
            ...(isProduction ? {} : { error: error.toString() }),
        };
    }
};

const sgdDiscoverAndGenerate = async (logger, data: SGDRequestData) => {
    try {
        if (!isDiscoverAndGenerateData(data)) {
            throw { message: `Invalid data`, code: StatusCodes.BAD_REQUEST };
        }
    } catch (checkFailedState) {
        logger.error(`SGD discoverAndGenerate failed: ${checkFailedState.message}`, { repoId: data?.repoId });
        return { status: 'error', code: checkFailedState.code };
    }

    // Run generation function
    logger.info('Discovering and generating', {
        repoId: data.repoId,
        ignoreDocumentIds: data.ignoreDocumentIds,
        fromDocumentIndex: data.fromDocumentIndex,
        toDocumentIndex: data.toDocumentIndex,
    });
    try {
        const { discoveredDocs, generatedDocs } = await discoverAndGenerateDocs(
            data.repoTarget,
            data.cloneToken,
            data.ignoreDocumentIds,
            data.fromDocumentIndex,
            // Ensure we never get pass the MAX_DOCUMENT_TO_RETURNth document
            data.toDocumentIndex ? Math.min(data.toDocumentIndex, MAX_DOCUMENTS_TO_RETURN) : MAX_DOCUMENTS_TO_RETURN,
            data.repoId
        );
        logger.info(
            `Discovered ${discoveredDocs.length} documents - returning the first ${Math.min(
                discoveredDocs.length,
                MAX_DOCUMENTS_TO_RETURN
            )}`,
            { repoId: data.repoId }
        );
        discoveredDocs.splice(MAX_DOCUMENTS_TO_RETURN);
        if (data.repoId) {
            setSGDObjectOnRepo(data.repoId, {
                [data.repoTarget.branchOrTag]: { numberOfDocuments: discoveredDocs.length },
            } as SGDRepoProperties);
        } else {
            logger.info('No repoId provided, not writing SGD properties to DB.');
        }
        return { status: 'success', generatedDocs };
    } catch (error) {
        logger.error(`SGD discoverAndGenerate failed`, { repoId: data.repoId, error });
        return {
            status: 'error',
            code: StatusCodes.INTERNAL_SERVER_ERROR,
            ...(isProduction ? {} : { error: error.toString() }),
        };
    }
};

export const sgdOnGeneratedDocSaved = functions.https.onCall(
    reportedHttpCallFunction({ name: 'sgdOnGeneratedDocSaved' }, async (logger, data, context) => {
        if (!context.auth) {
            logger.error('User is unauthenticated');
            return { status: 'error', code: StatusCodes.UNAUTHORIZED };
        }
        try {
            await sgdOnGeneratedDocSavedHandler(logger, data);
        } catch (error) {
            logger.error(`sgdOnGeneratedDocSaved failed`, { repoId: data?.repoId, error });
        }
        return { status: 'success' };
    })
);

export const inviteSwimmer = functions.https.onCall(
    reportedHttpCallFunction({ name: 'inviteSwimmer' }, async (logger, data, context) => {
        if (!context.auth) {
            logger.error('Invite request failed, user is unauthenticated');
            return { status: 'error', code: StatusCodes.UNAUTHORIZED };
        }
        const { workspaceId, emails, isWeb } = data;

        // Add to workspace.invites and use a workspace template for email
        const workspaceRef = await db.collection(`workspaces`).doc(workspaceId).get();
        if (!workspaceRef.exists) {
            logger.error(
                `Invite request failed, user ${context.auth.uid} is not authorized to invite to workspace ${workspaceId}`
            );
            return { status: 'error', code: StatusCodes.NOT_FOUND };
        }
        const workspace = workspaceRef.data();

        const workspaceUsersResponse = await db
            .collection(`workspaces`)
            .doc(workspaceId)
            .collection('workspace_users')
            .get();
        const workspaceUids = [];
        workspaceUsersResponse.forEach((user) => workspaceUids.push(user.id));
        if (!workspaceUids.includes(context.auth.uid)) {
            return { status: 'error', code: StatusCodes.UNAUTHORIZED };
        }
        const currentUserEmails = await getUsersEmails(workspaceUids);

        //  add invite if not invited already and not reached users limit
        const newInviteEmails = emails
            .filter((email) => !(workspace.invites && workspace.invites.includes(email)))
            .filter((email) => !currentUserEmails.includes(email));
        if (!workspace.invites || newInviteEmails.length > 0) {
            let usersLimit = DEFAULT_WORKSPACE_USERS_LIMIT; // use as default unless there's a billing account with a different value
            let billingAccountId = null;
            const billedWorkspaceRef = await db.collection(`billing_workspaces`).doc(workspaceId).get();
            if (billedWorkspaceRef.exists) {
                billingAccountId = billedWorkspaceRef.data().billing_account_id;
                const billingAccountRef = await db.collection(`billing_accounts`).doc(billingAccountId).get();
                if (billingAccountRef.exists) {
                    usersLimit = billingAccountRef.data().users_limit;

                    // fail invite if prohibited to invite an email with a different domain than the billing account
                    const domain = billingAccountRef.data().domain;
                    if (domain && !emails.every((email) => email.endsWith(`@${domain}`))) {
                        const domainSettingsRef = await db.collection(`domains`).doc(domain).get();
                        if (domainSettingsRef.exists) {
                            if (domainSettingsRef.data().isInviteToWorkspaceOutsideDomainProhibited) {
                                logger.error(`Invite request failed, workspace ${workspaceId} is outside of domain "${domain}"`);
                                return { status: 'error', code: StatusCodes.FORBIDDEN };
                            }
                        }
                    }
                }
            }

            let totalInvites = [...emails];
            // add the current user in case they were already counted before.
            totalInvites = totalInvites.concat(workspace.invites || []);
            totalInvites = totalInvites.concat(currentUserEmails);
            if (billingAccountId) {
                // get all workspaces under the billing account and sum their invites
                try {
                    const billingAccountWorkspaces = await db
                        .collection(`billing_workspaces`)
                        .where('billing_account_id', '==', billingAccountId)
                        .get();
                    for (const billingWorkspace of billingAccountWorkspaces.docs) {
                        if (billingWorkspace.id !== workspaceId) {
                            const billingWorkspaceRef = await db.collection(`workspaces`).doc(billingWorkspace.id).get();
                            if (billingWorkspaceRef.exists) {
                                const billingWorkspaceData = billingWorkspaceRef.data();
                                if (billingWorkspaceData.license !== billingPlanTypes.PRO) {
                                    totalInvites = totalInvites.concat(billingWorkspaceData.invites || []);
                                    const billingWorkspaceUsersResponse = await db
                                        .collection(`workspaces`)
                                        .doc(workspaceId)
                                        .collection('workspace_users')
                                        .get();
                                    const billingWorkspaceUids = [];
                                    billingWorkspaceUsersResponse.forEach((user) => billingWorkspaceUids.push(user.id));
                                    totalInvites = totalInvites.concat(await getUsersEmails(billingWorkspaceUids));
                                }
                            }
                        }
                    }
                } catch (err) {
                    logger.error(
                        `Invite request failed: failed calculating current invites usage for billing account ${billingAccountId}, error: ${err}`
                    );
                }
            }

            const actualInvitesCount = totalInvites.filter(
                (invitee, index) => index === totalInvites.indexOf(invitee)
            ).length;

            if (usersLimit >= actualInvitesCount || workspace.license === billingPlanTypes.PRO) {
                // actualInvitesCount includes current emails + the rest
                // add invitees to workspace
                logger.info(`Marking user(s) as invited to workspace ${workspaceId}: ${emails.join(', ')}`);
                const updateInvites = {
                    invites: admin.firestore.FieldValue.arrayUnion(...newInviteEmails),
                };
                await db.collection('workspaces').doc(workspaceId).update(updateInvites);
            } else {
                logger.error(`Invite request failed, workspace ${workspaceId} user limit reached`);
                return { status: 'error', code: StatusCodes.PAYMENT_REQUIRED };
            }
        }

        const user = await admin.auth().getUser(context.auth.uid);
        const nickname = user.displayName;
        const templateId = isWeb ? 'd-3d524b38a4ef4bbcb40566b6abaff1d1' : 'd-9d0e227629b74152a5dff223bec6e4b2';

        function generateButtonLink(email) {
            return isWeb
                ? `${getWebUrlHost()}/joinWorkspace/${workspaceId}?workspaceName=${encodeURIComponent(
                    workspace.name
                )}&email=${encodeURIComponent(email)}`
                : 'swimm.io/download';
        }

        try {
            await Promise.all(
                newInviteEmails.map(async (email) => {
                    const joinLink = generateButtonLink(email);
                    const emailMessage = {
                        from: {
                            name: 'Swimm',
                            email: 'donotreply@swimm.io',
                        },
                        templateId,
                        dynamic_template_data: {
                            nickname,
                            workspace: workspace.name,
                            btn_url: joinLink,
                        },
                    };
                    const msg = { to: email, ...emailMessage };
                    sendSGMail({ msg, context, purpose: 'invite to workspace' });

                    try {
                        const notification = {
                            action_url: joinLink,
                            created_at: FieldValue.serverTimestamp(),
                            emailed: true,
                            emailed_at: FieldValue.serverTimestamp(),
                            dismissed: false,
                            notifier_id: context.auth.uid,
                            notifier_name: nickname,
                            notifier_type: 'user',
                            recipient_email: email,
                            recipient_id: '',
                            seen: false,
                            slacked: false,
                            topic_id: workspaceId,
                            topic_name: workspace.name,
                            topic_type: 'workspace',
                            type: NOTIFICATION_TYPES.JOIN_WORKSPACE,
                        };
                        db.collection(firestoreCollectionNames.NOTIFICATIONS).add(notification);
                    } catch (err) {
                        logger.error(`Error creating notification for email ${email}: ${err}`);
                    }
                })
            );
            return { status: 'success', emailsAdded: newInviteEmails };
        } catch (e) {
            logger.warn(`Error sending email: ${e}`);
            return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
        }
    })
);

export const requestInvite = functions.https.onCall(
    reportedHttpCallFunction({ name: 'requestInvite' }, async (logger, data, context) => {
        const { workspaceId } = data;
        try {
            commonUtils.assertRequestAuthenticated(context);
            const workspaceRef = await commonUtils.getWorkspace(workspaceId);
            const workspace = workspaceRef.data();
            const user = await admin.auth().getUser(context.auth.uid);

            if (workspace['invite_requests'] && workspace['invite_requests'].includes(user.email)) {
                logger.info(`User ${user} already request an invite to workspace ${workspaceId}"`);
                return { code: StatusCodes.OK };
            }

            await db
                .collection('workspaces')
                .doc(workspaceId)
                .update({
                    invite_requests: admin.firestore.FieldValue.arrayUnion(user.email),
                });

            await emailWorkspaceAdmins({
                workspaceId,
                templateId: 'd-c84d3d72b0944ba7bf054ee9ab55a94a',
                templateData: {
                    full_name: user.displayName,
                    nickname: user.displayName,
                    workspace: workspace.name,
                    email: user.email,
                    btn_url: `${getWebUrlHost()}/workspaces/${workspaceId}?open-invites=true`,
                },
            });
            return { status: 'success' };
        } catch (error) {
            logger.error(
                `An error has occurred. Details: ${error.message}, stopping call with params: ${JSON.stringify(data)}`
            );
            return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
        }
    })
);

export const removeInviteRequest = functions.https.onCall(
    reportedHttpCallFunction({ name: 'removeInviteRequest' }, async (logger, data, context) => {
        const { workspaceId, email } = data;

        try {
            commonUtils.assertRequestAuthenticated(context);
            await commonUtils.assertWorkspaceAdmin(context, workspaceId);
            const workspaceRef = await commonUtils.getWorkspace(workspaceId);
            const workspace = workspaceRef.data();

            if (workspace['invite_requests'] && !workspace['invite_requests'].includes(email)) {
                logger.info(`User ${email} did not request to be invited to workspace ${workspaceId}`);
                return { status: 'success', code: StatusCodes.OK };
            }

            await db
                .collection('workspaces')
                .doc(workspaceId)
                .update({
                    invite_requests: admin.firestore.FieldValue.arrayRemove(email),
                });

            return { status: 'success' };
        } catch (error) {
            logger.error(
                `An error has occurred. Details: ${error.message}, stopping call with params: ${JSON.stringify(data)}`
            );
            return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
        }
    })
);

export const sendWelcomeEmail = functions.https.onCall(
    reportedHttpCallFunction({ name: 'sendWelcomeEmail' }, async (logger, data, context) => {
        if (!context.auth) {
            logger.error(`Error sending welcome email. The provided email "${data.email}" is not of an authorised user`);
            return { status: 'error', code: StatusCodes.UNAUTHORIZED };
        }
        const { isWeb, isMobile } = data;
        const email = context.auth.token && context.auth.token.email;
        const user = await admin.auth().getUser(context.auth.uid);
        const nickname = user.displayName;

        const webMailTemplate = isMobile ? 'd-805902e4599c46beb354447f0246c08c' : 'd-d8ec4521de614d71ab978ebe59aea227';

        const customTemplateFields = isWeb
            ? { btn_url: getWebUrlHost(), templateId: webMailTemplate }
            : { btn_url: 'swimm.io/download', templateId: 'd-9d0e227629b74152a5dff223bec6e4b2' };

        const msg = {
            to: email,
            from: {
                name: 'Swimm',
                email: 'donotreply@swimm.io',
            },
            dynamic_template_data: {
                nickname,
                btn_url: customTemplateFields.btn_url,
            },
            templateId: customTemplateFields.templateId,
        };
        try {
            await sendSGMail({ msg, context, purpose: 'welcome email' });

            return { status: 'success' };
        } catch (e) {
            logger.error(`Error sending welcome email: ${e}`);
            return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
        }
    })
);

export const badge = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'badge' }, (logger, req, res) => {
        return res.redirect(302, `https://img.shields.io/badge/Swimm-2%20Heats-purple.svg`);
    })
);

function isLinkOrDoc(collectionName, documentObj) {
    return (
        collectionName === 'swimms' &&
        'type' in documentObj &&
        (documentObj.type === 'external_link' || documentObj.type === 'doc')
    );
}

const closedWonDocs = 5;
const closedWonFirstDoc = 1;
async function sendSalesforceDocNumberEvent(workspaceId, totalDocCount, logger) {
    if (totalDocCount === closedWonDocs || totalDocCount === closedWonFirstDoc) {
        // send event to salesforce: X1 Docs Created/ X5 Docs Created
        logger.debug(`Send event to salesforce: X${totalDocCount} Docs Created`);

        const salesforceOperationResult = await salesforceFunctions.updateExistingWorkspaceInSalesforce({
            workspaceId,
            closedWonDocs: totalDocCount === closedWonDocs,
            closedWonFirstDoc: totalDocCount === closedWonFirstDoc,
        });
        const salesforceEventSent = salesforceOperationResult && salesforceOperationResult.status === 'success';
        if (!salesforceEventSent) {
            logger.error(`Error sending event to salesforce: ${JSON.stringify(salesforceOperationResult)}`);
        }
        try {
            logger.debug(`Updating doc count analytics for workspace ${workspaceId}`);
            await db
                .collection(firestoreCollectionNames.ANALYTICS)
                .doc(workspaceId)
                .set(
                    {
                        [`doc_count_${totalDocCount}_event_sent`]: salesforceEventSent,
                        [`doc_count_${totalDocCount}_date`]: FieldValue.serverTimestamp(),
                    },
                    { merge: true }
                );
        } catch (error) {
            logger.error(`Failed saving data in DB, error ${error}`);
        }
    }
}

async function incrementTotalDocsCounter(repoRef, repoId, logger) {
    const repo = (await repoRef.get()).data();
    if (repo.is_private) {
        const workspacesContainingTheRepo = await db
            .collection(firestoreCollectionNames.WORKSPACES)
            .where('repositories', 'array-contains', repoId)
            .get();
        if (
            workspacesContainingTheRepo &&
            workspacesContainingTheRepo.docs &&
            workspacesContainingTheRepo.docs.length > 0
        ) {
            const workspaceId = workspacesContainingTheRepo.docs[0].id;
            const workspaceAnalyticsRef = await db.collection(firestoreCollectionNames.ANALYTICS).doc(workspaceId).get();
            if (workspaceAnalyticsRef.exists && workspaceAnalyticsRef.data().total_doc_count) {
                logger.debug(`Incrementing total_doc_count for workspace ${workspaceId}`);
                await db
                    .collection(firestoreCollectionNames.ANALYTICS)
                    .doc(workspaceId)
                    .update({ total_doc_count: admin.firestore.FieldValue.increment(1) });

                await sendSalesforceDocNumberEvent(workspaceId, workspaceAnalyticsRef.data().total_doc_count + 1, logger);
            } else {
                await db
                    .collection(firestoreCollectionNames.ANALYTICS)
                    .doc(workspaceId)
                    .set({ total_doc_count: 1 }, { merge: true });

                await sendSalesforceDocNumberEvent(workspaceId, 1, logger);
            }
        }
    }
}

export const handleNewContribution = functions.firestore
    .document(`repositories/{repoId}/swimms/{unitId}/contributions/{contributionId}`)
    .onCreate(
        reportedFirestoreFunction({ name: 'handleNewContribution' }, async (logger, snapshot, context) => {
            const { repoId, unitId } = context.params;
            const createdContribution = snapshot.data();
            const userId = createdContribution.creator;
            const docRef = snapshot.ref.parent.parent;
            const docData = (await docRef.get()).data();
            const contributor = {
                user_id: createdContribution.creator,
                name: createdContribution.creator_name,
                modified: createdContribution.created,
                is_creator: createdContribution.creator === docData.creator,
            };
            const contributorsRef = docRef.collection('contributors');
            contributorsRef.doc(userId).set(contributor, { merge: true });
            logger.debug(`set contributor to repositories/${repoId}/swimms/${unitId}/contributors ${userId}`);
        })
    );

// this will generate a new list of assignees whenever an assignment is added / updated / develted
export const handleAssignmentUpdate = functions.firestore
    .document(`repositories/{repoId}/swimms/{unitId}/assignments/{assignmentId}`)
    .onWrite(
        reportedFirestoreFunction({ name: 'handleAssignmentUpdate' }, async (logger, snapshot, context) => {
            const { repoId, unitId } = context.params;
            const item = snapshot.after && snapshot.after.exists ? snapshot.after : snapshot.before;
            const assignmentsRefs = await db
                .collection(`repositories/${repoId}/swimms/${unitId}/assignments`)
                .where('completed', '==', false)
                .get();
            const assigneesSet = new Set();
            assignmentsRefs.forEach((assignmentRef) => {
                assigneesSet.add(assignmentRef.data().assignee_email);
            });
            const assignees = [...assigneesSet];
            item.ref.parent.parent.update({ assignees });

            logger.debug(`set assignees to repositories/${repoId}/swimms/${unitId} [${assignees.join(',')}]`);
        })
    );

export const emailAssignee = functions.https.onCall(
    reportedHttpCallFunction({ name: 'emailAssignee' }, async (logger, data, context) => {
        const { workspaceId, docUrl, docTitle, assignment } = data;
        try {
            const templateId = 'd-0cf03e4f1e434d6493c55ac28489a5cd';
            const btnUrl = assignment.type === 'Needs updating' ? docUrl + '/edit' : docUrl;
            const msg = {
                to: assignment.assignee_email,
                from: {
                    name: 'Swimm',
                    email: 'donotreply@swimm.io',
                },
                dynamic_template_data: {
                    nickname: assignment.assigned_by_name || assignment.assigned_by_email,
                    btn_url: btnUrl,
                    assign_type: assignment.type,
                    assign_notes: assignment.description ? assignment.description : 'N/A',
                    doc_title: docTitle,
                    workspace_id: workspaceId,
                },
                templateId: templateId,
            };
            await sendSGMail({ msg, context, purpose: 'assignment' });
            return { status: 'success' };
        } catch (error) {
            logger.error(
                `An error has occurred. Details: ${error.message}, stopping call with params: ${JSON.stringify(data)}`
            );
            return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
        }
    })
);

export const increamentCountersInRepo = functions.firestore
    .document(`repositories/{repoId}/{collectionName}/{docId}`)
    .onCreate(
        reportedFirestoreFunction({ name: 'incrementCounter' }, async (logger, snapshot, context) => {
            const { repoId, collectionName } = context.params;
            const createdDoc = snapshot.data();

            // Skip external links in count
            if (isLinkOrDoc(collectionName, createdDoc)) {
                return;
            }

            const increment = admin.firestore.FieldValue.increment(1);
            logger.debug(`Incrementing counter_${collectionName} for repo ${repoId}`);
            snapshot.ref.parent.parent.update({ [`counter_${collectionName}`]: increment });

            if (collectionName === 'swimms') {
                await incrementTotalDocsCounter(snapshot.ref.parent.parent, repoId, logger);
            }
        })
    );

export const decrementCountersInRepo = functions.firestore
    .document(`repositories/{repoId}/{collectionName}/{docId}`)
    .onDelete(
        reportedFirestoreFunction({ name: 'decrementCounter' }, async (logger, snapshot, context) => {
            const { collectionName } = context.params;
            const deletedDoc = snapshot.data();

            // Skip external links in count
            if (isLinkOrDoc(collectionName, deletedDoc)) {
                return;
            }

            const decrement = admin.firestore.FieldValue.increment(-1);
            logger.debug(`Decrementing counter_${collectionName}`);
            snapshot.ref.parent.parent.update({ [`counter_${collectionName}`]: decrement });
        })
    );

export const removeSwimmFromPlaylist = functions.firestore.document(`repositories/{repoId}/swimms/{docId}`).onDelete(
    reportedFirestoreFunction({ name: 'removeSwimmFromPlaylist' }, async (logger, snapshot, context) => {
        const deletedUnitID = snapshot.id;
        logger.debug(`About to remove Swimm unit ${deletedUnitID} from playlists containing it`);
        const { repoId } = context.params;
        const playlistsContainingTheUnit = await db
            .collection(`repositories/${repoId}/playlists`)
            .where('sequence', 'array-contains', deletedUnitID)
            .get();
        const repoRef = snapshot.ref.parent.parent;
        // Iterate the playlists in the repo to find if the deleted swimm should be deleted from any of them
        playlistsContainingTheUnit.forEach((playlistDoc) => {
            logger.info(`Removing Swimm unit ${deletedUnitID} from playlist ${playlistDoc.id}`);
            repoRef
                .collection(`playlists`)
                .doc(playlistDoc.id)
                .update('sequence', FieldValue.arrayRemove(deletedUnitID))
                .then(() => {
                    return repoRef.get();
                });
        });
    })
);

const bucket = 'gs://swimmio_backup';

export const scheduledFirestoreExport = functions.pubsub.schedule('every 72 hours').onRun(
    reportedScheduledFunction({ name: 'scheduledFirestoreExport' }, async (logger) => {
        const databaseName = client.databasePath(projectId, '(default)');
        return client
            .exportDocuments({
                name: databaseName,
                outputUriPrefix: bucket,
                // Leave collectionIds empty to export all collections
                // or set to a list of collection IDs to export,
                // collectionIds: ['users', 'posts']
                collectionIds: [],
            })
            .then((responses) => {
                const response = responses[0];
                logger.info(`Export success: ${response['name']}`);
            })
            .catch((err) => {
                logger.error(`Export error: ${err}`);
                throw new Error('Export operation failed');
            });
    })
);

export const incrementResourceViews = functions.https.onCall(
    reportedFirestoreFunction({ name: 'incrementResourceViews' }, async (logger, data) => {
        const { resourceId } = data;
        logger.info(`Incrementing view counter for resource with ID ${resourceId}`);
        try {
            const resource = await getResourceFromResourcePath(resourceId);
            const increment = admin.firestore.FieldValue.increment(1);
            return resource.update({ [`views`]: increment });
        } catch (error) {
            logger.error(`Failed to increment views counter for resource with ID ${data}:${error}`);
            throw error;
        }
    })
);

export const incrementUpvote = functions.firestore.document(`upvotes/{uid}/user_upvotes/{docId}`).onCreate(
    reportedFirestoreFunction({ name: 'incrementUpvote' }, async (logger, snapshot, context) => {
        const { docId } = context.params;
        logger.info(`Incrementing upvote counter for resource with ID ${docId}`);
        try {
            const resource = await getResourceFromResourcePath(docId);
            const increment = admin.firestore.FieldValue.increment(1);
            return resource.update({ [`counter_upvotes`]: increment });
        } catch (error) {
            logger.error(`Failed to increment upvote counter for resource with ID ${docId}: ${error}`);
            throw error;
        }
    })
);

export const decrementUpvote = functions.firestore.document(`upvotes/{uid}/user_upvotes/{docId}`).onDelete(
    reportedFirestoreFunction({ name: 'decrementUpvote' }, async (logger, snapshot, context) => {
        const { docId } = context.params;
        logger.info(`Decrementing upvote counter for resource with ID ${docId}`);
        try {
            const resource = await getResourceFromResourcePath(docId);
            const decrement = admin.firestore.FieldValue.increment(-1);
            return resource.update({ [`counter_upvotes`]: decrement });
        } catch (error) {
            logger.error(`Failed to increment upvote counter for resource with ID ${docId}: ${error}`);
            throw error;
        }
    })
);

async function getResourceFromResourcePath(docId) {
    // upvote Id format: ContainerType-ContainerId-ResourceType-ResourceId, e.g repo-1234-playlist-5678, workspace-1234-plan-5678
    const splittedUpvote = docId.split('-');
    let containerType = splittedUpvote[0];
    const containerId = splittedUpvote[1];
    let resourceType = splittedUpvote[2];
    const resourceId = splittedUpvote[3];

    if (containerType === 'repo') {
        containerType = 'repositories';
        if (resourceType === 'swimm') {
            resourceType = 'swimms';
        } else {
            resourceType = 'playlists';
        }
    } else {
        containerType = 'workspaces';
        resourceType = 'plans';
    }
    return await db.collection(containerType).doc(containerId).collection(resourceType).doc(resourceId);
}

export const incrementWorkspaceCounter = functions.firestore
    .document(`workspaces/{workspaceId}/{collectionName}/{docId}`)
    .onCreate(
        reportedFirestoreFunction({ name: 'incrementWorkspaceCounter' }, async (logger, snapshot, context) => {
            const { collectionName } = context.params;
            const increment = admin.firestore.FieldValue.increment(1);
            logger.debug(`Incrementing workspace counter_${collectionName}`);
            return snapshot.ref.parent.parent.update({ [`counter_${collectionName}`]: increment });
        })
    );

export const decrementWorkspaceCounter = functions.firestore
    .document(`workspaces/{workspaceId}/{collectionName}/{docId}`)
    .onDelete(
        reportedFirestoreFunction({ name: 'decrementWorkspaceCounter' }, async (logger, snapshot, context) => {
            const { collectionName } = context.params;
            const decrement = admin.firestore.FieldValue.increment(-1);
            logger.debug(`Decrementing workspace counter_${collectionName}`);
            return snapshot.ref.parent.parent.update({ [`counter_${collectionName}`]: decrement });
        })
    );

export const updateReposStats = functions.pubsub.topic('calcRepoStats').onPublish(
    reportedTopicFunction({ name: 'updateReposStats' }, async (logger) => {
        const date = new Date();
        const formattedDate = date.toISOString();
        logger.debug(`Triggered at: ${formattedDate}`);
        const repositories = await db.collection('repositories').get();
        await Promise.all(
            repositories.docs.map(async (repository) => {
                let hunks_count = 0;
                const swimms = await db.collection(`repositories`).doc(repository.id).collection('swimms').get();
                if (!swimms.empty) {
                    const reducer = (hunksCount, currentSwimm) => {
                        return hunksCount + (currentSwimm.data().hunks_count ? currentSwimm.data().hunks_count : 0);
                    };
                    hunks_count = swimms.docs.reduce(reducer, 0);
                }
                const stats = {
                    hunks_count: hunks_count,
                    date: admin.firestore.Timestamp.fromDate(date),
                };
                await db.collection('repositories').doc(repository.id).collection('stats').doc(formattedDate).set(stats);
            })
        );
    })
);

export const githubAuth = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'githubAuth' }, async (logger, req, res) => {
        cors(req, res, async () => {
            const userRef = await db.collection(`users`).doc(req.query.id).get();
            if (userRef.exists) {
                const state = userRef.data().state;
                if (req.query.state === state) {
                    const { client_id, client_secret } = functions.config().github;
                    const auth = createOAuthAppAuth({
                        clientId: client_id,
                        clientSecret: client_secret,
                    });
                    const tokenAuthentication = await auth({
                        type: 'token',
                        code: req.query.code,
                        state: state,
                    });

                    const redirect = userRef.data().redirect;
                    const isLocal =
                        redirect && (redirect.indexOf('localhost') > 0 || redirect.indexOf('https://swimm-web-app--') === 0); // double dashes are added to staging branch preview
                    const finalRedirect = isLocal ? `${redirect}/setGithubToken?token=${tokenAuthentication.token}` : null;

                    const finalCommand = finalRedirect
                        ? `window.location.href='${finalRedirect}';`
                        : 'var myWindow=window.open("", "_self");myWindow.document.write("");setTimeout(function(){myWindow.close();},1000);';
                    const dbName = isProduction ? 'swimm_state' : 'swimm_state_staging';
                    const script = finalRedirect
                        ? finalCommand
                        : `
          try {
            var request = indexedDB.open('swimm');
            request.onsuccess = function (event){
              event.target.result.transaction(['${dbName}'],'readwrite').objectStore('${dbName}').put('${tokenAuthentication.token}','gh_token');
              ${finalCommand}
            };
            request.onerror = function (ev){
              ${finalCommand}
            };
          } catch (e) {
            ${finalCommand}
          }`;
                    const html = `<html><head><script>${script}</script></head><body></body></html>`;
                    logger.info(`GitHub auth success for user ${req.query.id}`);
                    res.status(StatusCodes.OK).send(html);
                } else {
                    logger.info(`State not matching for user ${req.query.id}`);
                }
            } else {
                logger.info(`State not found in DB for user ${req.query.id}`);
            }
        });
    })
);

export const getGitlabConfig = functions.https.onCall(
    reportedHttpCallFunction({ name: 'getGitlabConfig' }, async (logger, data, context) => {
        commonUtils.assertRequestAuthenticated(context);

        const { host } = data;
        logger.info('returning configuration for host ' + host);
        const secrets = functions.config().gitlab;
        const hostConfig = host ? secrets[host] : secrets;

        return {
            host: hostConfig.host,
            applicationId: hostConfig.application_id,
        };
    })
);

export const gitlabAuth = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'gitlabAuth' }, async (logger, req, res) => {
        cors(req, res, async () => {
            try {
                const userRef = await db.collection(`users`).doc(req.query.id).get();
                if (userRef.exists) {
                    const state = userRef.data().state;
                    if (req.query.state === state) {
                        const host = req.query.host;
                        const secrets = functions.config().gitlab;
                        const hostConfig = host ? secrets[host] : secrets;
                        if (!hostConfig) {
                            throw new Error('Could not find configuration for host ' + host);
                        }

                        const redirectURI = encodeURIComponent(
                            getWebUrlHost() + '/gitlabAuth?id=' + req.query.id + (host ? '&host=' + req.query.host : '')
                        );
                        const url =
                            hostConfig.host +
                            '/oauth/token?grant_type=authorization_code&client_id=' +
                            hostConfig.application_id +
                            '&client_secret=' +
                            hostConfig.secret +
                            '&code=' +
                            req.query.code +
                            '&redirect_uri=' +
                            redirectURI;
                        const response = await fetch(url, {
                            method: 'POST',
                        });
                        const tokenObj = await response.json();
                        const token = tokenObj.access_token;
                        const redirect = userRef.data().redirect;
                        const isLocal = redirect && redirect.indexOf('localhost') > 0;
                        const finalRedirect = isLocal ? `${redirect}/setGitlabToken?token=${token}` : null;

                        const finalCommand = finalRedirect
                            ? `window.location.href='${finalRedirect}';`
                            : 'var myWindow=window.open("", "_self");myWindow.document.write("");setTimeout(function(){myWindow.close();},1000);';
                        const dbName = isProduction ? 'swimm_state' : 'swimm_state_staging';
                        const script = finalRedirect
                            ? finalCommand
                            : `
            try {
              var request = indexedDB.open('swimm');
              request.onsuccess = function (event){
                event.target.result.transaction(['${dbName}'],'readwrite').objectStore('${dbName}').put('${token}','gl_token');
                ${finalCommand}
              };
              request.onerror = function (ev){
                ${finalCommand}
              };
            } catch (e) {
              ${finalCommand}
            }`;
                        const html = `<html><head><script>${script}</script></head><body></body></html>`;
                        logger.info(`GitHub auth success for user ${req.query.id}`);
                        res.status(StatusCodes.OK).send(html);
                    } else {
                        logger.info(`State not matching for user ${req.query.id}`);
                    }
                } else {
                    logger.info(`State not found in DB for user ${req.query.id}`);
                }
            } catch (err) {
                logger.error(err);
                res.status(StatusCodes.INTERNAL_SERVER_ERROR).send();
            }
        });
    })
);

export const getStatusPageLink = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'getStatusPageLink' }, async (logger, req, res) => {
        cors(req, res, async () => {
            try {
                const { branch, repoId, localStatusPageLink } = req.body;
                if (!repoId || !localStatusPageLink || !branch) {
                    logger.error(
                        `request missing some arguments. repoId: "${repoId}", local Status Link: "${localStatusPageLink}", branch: "${branch}"`
                    );
                    res.status(StatusCodes.BAD_REQUEST).send({
                        errorMessage: `Error occurred while generating the link. Make sure you send all required arguments`,
                    });
                    return;
                }
                let link = localStatusPageLink;
                const workspacesContainingTheRepo = await db
                    .collection(`workspaces`)
                    .where('repositories', 'array-contains', repoId)
                    .get();

                // Assuming first workspace with "is_web" is the relevant one
                for (const workspaceQueryDocumentSnapshot of workspacesContainingTheRepo.docs) {
                    const workspaceId = workspaceQueryDocumentSnapshot.id;
                    const workspaceDoc = await db.collection(`workspaces`).doc(workspaceId).get();
                    if (workspaceDoc.data().is_web) {
                        link = `${getWebUrlHost()}/repos/${repoId}/branch/${encodeURIComponent(branch)}/status`;
                        break;
                    }
                }
                // redirect to app home page
                res.status(StatusCodes.OK).send({ link: link });
            } catch (error) {
                logger.error(`Failed to get status page link: ${error}`);
                res
                    .status(StatusCodes.INTERNAL_SERVER_ERROR)
                    .send({ errorMessage: `Error occurred while generating the link` });
            }
        });
    })
);

// For production env only we set mandatory default resources to avoid "cold starts" and out of memory issues
const githubAppRuntimeOpts: functions.RuntimeOptions = isProduction
    ? { minInstances: 4, memory: '4GB', timeoutSeconds: 540 }
    : {};

export const githubWebhook = functions.runWith(githubAppRuntimeOpts).https.onRequest(
    reportedHttpRequestFunction(
        { name: 'githubWebhook', excludeFieldsFromEntryLog: ['pull_request'], disableSentry: true }, // disabling sentry since it's loud
        async (logger, req, res) => {
            cors(req, res, async () => {
                try {
                    const app_id = functions.config().github_app.app_id;
                    const private_key = functions.config().github_app.private_key;
                    await githubApp(req, app_id, private_key);
                    res.status(StatusCodes.OK, { 'content-type': 'application/json' });
                    res.end('{"ok":true}');
                } catch (error) {
                    logger.error(`Github app: request failed: ${error} (request: ${req})`);
                    res.status(StatusCodes.INTERNAL_SERVER_ERROR).send({ errorMessage: `Error occurred` });
                }
            });
        }
    )
);

/**
 * Webhook handling GitHub marketplace plan events for the Swimm GitHub app
 */
export const githubMarketplaceListingWebhook = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'githubMarketplaceWebhook', disableSentry: true }, async (logger, req, res) => {
        cors(req, res, async () => {
            try {
                await marketplaceGitHubAppHandler(req);
                res.status(StatusCodes.OK, { 'content-type': 'application/json' });
                res.end('{"ok":true}');
            } catch (error) {
                logger.error(`GitHub app marketplace: request failed: ${error} (request: ${req})`);
                res.status(StatusCodes.INTERNAL_SERVER_ERROR).send({ errorMessage: `Error occurred` });
            }
        });
    })
);

export const logEvent = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'logEvent' }, async (logger, req, res) => {
        try {
            const { repoId, logMessage } = req.body;
            await logEventCloud(repoId, logMessage, db, logger);
        } catch (error) {
            logger.error(`Failed to write event log: ${error}`);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).end();
            return;
        }
        res.status(StatusCodes.OK).end();
    })
);

export const broadcastWorkspaceCreation = functions.firestore.document(`workspaces/{workspaceId}`).onCreate(
    reportedFirestoreFunction({ name: 'broadcastWorkspaceCreation' }, async (logger, snapshot) => {
        if (!isProduction) {
            return;
        }
        const createdWorkspace = snapshot.data();
        const msg = {
            to: 'updates@swimm.io',
            from: {
                name: 'Swimm updates',
                email: 'donotreply@swimm.io',
            },
            subject: `A New Workspace Was Created`,
            text: `Workspace ${createdWorkspace.name} was created by ${createdWorkspace.creator_name}`,
        };
        try {
            await sendSGMail({ msg, purpose: 'workspace creation', category: 'Internal - Slack Notification' });
        } catch (e) {
            logger.error(`Error sending update email: ${e}`);
        }
    })
);

export const subscribeToProPlan = functions.https.onCall(
    reportedHttpCallFunction(
        { name: 'subscribeToProPlan', excludeFieldsFromEntryLog: ['taxId', 'companyName', 'email', 'paymentMethod'] },
        async (logger, data, context) => {
            const workspaceId = data.workspaceId;
            if (!(await commonUtils.isWorkspaceAdmin(context, workspaceId))) {
                const uid = context && context.auth && context.auth.uid;
                logger.error(`User ${uid} is not an admin in workspace ${workspaceId}`);
                return null;
            }

            const subscription = await subscribeWorkspaceToProPlan(db, data);
            if (subscription) {
                logger.info(`Created subscription with ID ${subscription.subscription.id}`);
                await updateWorkspaceBilling(db, workspaceId, subscription.subscription);
                logger.info(
                    `Created billing account for workspace ${workspaceId} with subscription ${subscription.subscription.id}`
                );
                return { status: 'success' };
            }
            logger.error(`Could not create subscription for workspace: ${workspaceId}`);
            return { status: 'error' };
        }
    )
);

export const billingConfig = functions.https.onCall(
    reportedHttpCallFunction({ name: 'billingConfig' }, async () => {
        return await fetchBillingConfig();
    })
);

export const acceptInvitation = functions.https.onCall(
    reportedHttpCallFunction({ name: 'acceptInvitation' }, async (logger, data, context) => {
        const { workspaceId, user } = data;

        logger.debug(`Checking if user ${user.uid} is invited to workspace ${workspaceId}`);
        const workspaceRef = await db.collection('workspaces').doc(workspaceId).get();
        const workspaceInvites = workspaceRef && workspaceRef.exists && workspaceRef.data().invites;

        if (!context.auth || context.auth.uid !== user.uid || !workspaceInvites.includes(user.email)) {
            logger.error(`User ${user.uid} is not logged in, or was not invited to workspace ${workspaceId}`);
            return false;
        }

        const userData = {
            created: FieldValue.serverTimestamp(),
            creator: user.uid,
            creator_name: user.nickname,
            modified: FieldValue.serverTimestamp(),
            modifier: user.uid,
            modifier_name: user.nickname,
            id: context.auth.uid,
            name: user.nickname,
            email: user.email,
            uid: context.auth.uid,
        };
        logger.debug(`Adding user ${user.uid} to workspace ${workspaceId}`);
        try {
            await db.collection('workspaces').doc(workspaceId).collection('workspace_users').doc(user.uid).set(userData);
        } catch (err) {
            logger.error(`Failed to add user ${user.uid} to workspace ${workspaceId}: ${err}`);
            return false;
        }

        logger.debug(`Removing user ${user.uid} invite from workspace ${workspaceId}`);
        try {
            if (workspaceInvites) {
                await db
                    .collection('workspaces')
                    .doc(workspaceId)
                    .update({
                        invites: FieldValue.arrayRemove(user.email),
                    });
            }
        } catch (err) {
            logger.error(`Failed to update workspace ${workspaceId} invites: ${err}`);
        }

        logger.debug(`Started updateSubscriptionQuantity using ${JSON.stringify(data)}`);
        await updateSubscriptionQuantity(db, workspaceId);

        try {
            const response = await db
                .collection(firestoreCollectionNames.NOTIFICATIONS)
                .where('recipient_email', '==', user.email)
                .get();

            const notifications = response.docs
                .map((doc) => Object.assign(doc.data(), { id: doc.id }))
                .filter(
                    (doc) =>
                        doc.topic_id === workspaceId &&
                        doc.topic_type === 'workspace' &&
                        doc.type === NOTIFICATION_TYPES.JOIN_WORKSPACE &&
                        !doc.dismissed
                );

            await Promise.all(
                notifications.map(async (notification) => {
                    logger.debug(`removing notification ${notification.id}`);
                    await db
                        .collection(firestoreCollectionNames.NOTIFICATIONS)
                        .doc(notification.id)
                        .update({ dismissed: true, dismissed_at: FieldValue.serverTimestamp() });
                    logger.debug(`removed notification ${notification.id}`);
                })
            );
        } catch (err) {
            logger.error(`Failed to update notifications for user ${user.email} in workspace ${workspaceId}: ${err}`);
        }

        logger.info(`Finished adding new user to workspace ${workspaceId}`);
        return true;
    })
);

export const fetchSubscriptionInfo = functions.https.onCall(
    reportedHttpCallFunction({ name: 'fetchSubscriptionInfo' }, async (logger, data, context) => {
        const workspaceId = data.workspaceId;

        if (!(await commonUtils.isWorkspaceAdmin(context, workspaceId))) {
            const uid = context && context.auth && context.auth.uid;
            logger.error(`User ${uid} is not an admin in workspace ${workspaceId}`);
            return null;
        }

        return await fetchSubscriptionData(db, workspaceId);
    })
);

const stripeEventsToBillingDataMapper = {
    'charge.failed': (event) => event.billing_details.name,
    'payment_intent.payment_failed': (event) => event.charges.data[0].billing_details.name,
    'invoice.payment_failed': (event) => event.customer_name,
};

const stripeEventsToErrorMapper = {
    'charge.failed': (event) => ({ ...event.outcome, failure_message: event.failure_message }),
    'payment_intent.payment_failed': (event) => ({
        ...event.charges.data[0].outcome,
        failure_message: event.charges.data[0].failure_message,
    }),
    'invoice.payment_failed': () => 'no reason found',
};

export const stripeErrorWebhook = functions.https.onRequest(
    reportedHttpRequestFunction({ name: 'stripeErrorWebhook' }, async (logger, req, res) => {
        cors(req, res, async () => {
            const event = req.body.data.object;
            const eventType = req.body.type;

            // For event types we don't support (shouldn't happen)
            if (!stripeEventsToBillingDataMapper[eventType]) {
                res.status(StatusCodes.NOT_FOUND).end();
                return;
            }

            logger.error(
                `Got event ${eventType} for customer ${stripeEventsToBillingDataMapper[eventType](
                    event
                )} with reasons: ${JSON.stringify(stripeEventsToErrorMapper[eventType](event))}`
            );

            const msg = {
                to: 'updates@swimm.io',
                from: {
                    name: 'Swimm',
                    email: 'donotreply@swimm.io',
                },
                templateId: 'd-19cb6c9fe15a4b659de19a9d46d45e1b',
                dynamic_template_data: {
                    event_type: req.body.type,
                    event_data: JSON.stringify(event, null, 4),
                },
            };
            try {
                await sendSGMail({ msg, purpose: 'stripe payment error' });
                res.status(StatusCodes.OK).end();
            } catch (e) {
                logger.error(`Error sending billing-failure email to Swimm billing personnel: ${e}`);
                res.status(StatusCodes.INTERNAL_SERVER_ERROR).end();
            }
        });
    })
);

const tryDeleteUser = async (userId, workspaceId, innerCollection) => {
    try {
        await db.collection('workspaces').doc(workspaceId).collection(innerCollection).doc(userId).delete();
    } catch (err) {
        return err;
    }
};

export const removeUserFromWorkspace = functions.https.onCall(
    reportedHttpCallFunction({ name: 'removeUserFromWorkspace' }, async (logger, data, context) => {
        if (!context.auth.uid) {
            logger.error(`No UID in context, stopping call with params: ${JSON.stringify(data)}`);
            return false;
        }

        if (context.auth.uid !== data.userId) {
            if (!(await commonUtils.isWorkspaceAdmin(context, data.workspaceId))) {
                logger.error(`Non-admin user ${context.auth.uid} attempted to delete user ${data.userId}`);
                return false;
            }
        }

        let err = await tryDeleteUser(data.userId, data.workspaceId, 'workspace_users');
        if (err) {
            logger.error(`Error removing user ${data.userId}: ${err}`);
            return false;
        }

        // If user is also an admin, remove from workspace admins as well
        const user = await db
            .collection('workspaces')
            .doc(data.workspaceId)
            .collection('workspace_admins')
            .doc(data.userId)
            .get()
            .catch((err) => logger.error(`DB query error: ${err}`));

        if (user && user.exists) {
            err = await tryDeleteUser(data.userId, data.workspaceId, 'workspace_admins');
            if (err) {
                logger.error(`Error removing admin ${data.userId}: ${err}`);
            }
        }

        logger.info(`Updating Stripe subscription for workspace ${data.workspaceId}`);
        await updateSubscriptionQuantity(db, data.workspaceId);

        logger.info(`User ${data.userId} removed from workspace ${data.workspaceId}`);
        return true;
    })
);

export const updateRepositoryDocumentFields = functions.https.onCall(
    reportedHttpCallFunction({ name: 'updateRepositoryDocumentFields' }, async (logger, data, context) => {
        try {
            // The only keys that the client can send to update
            const repoUpdateAllowedKeys = ['integrations', 'modifier_name', 'notify'];

            commonUtils.assertRequestAuthenticated(context);
            commonUtils.assertUpdateFieldsInAllowedList(data.fieldsToUpdate, repoUpdateAllowedKeys);
            await commonUtils.getWorkspace(data.workspaceId); // Asserts and throws if the workspace doesn't exist
            await commonUtils.assertWorkspaceAdmin(context, data.workspaceId);

            const updatedFieldsAndValues = ['modified', FieldValue.serverTimestamp(), 'modifier', context.auth.uid];
            for (const [key, value] of Object.entries(data.fieldsToUpdate)) {
                updatedFieldsAndValues.push(key, value);
            }
            const repoRef = await commonUtils.getRepo(data.repoId);
            // @ts-ignore
            await repoRef.ref.update(...updatedFieldsAndValues);
            logger.info(`Updated repo document ${data.repoId} with fields: ${Object.keys(data.fieldsToUpdate)}`);
            return { status: 'success' };
        } catch (error) {
            logger.error(`Error: ${error.message}`);
            const errorStatusCode = resourcesErrors[error.code]
                ? resourcesErrors[error.code].statusCode
                : resourcesErrors.DEFAULT_ERROR.statusCode;
            return { status: 'error', code: errorStatusCode, message: 'Update to repository failed' };
        }
    })
);

export const addRepoToWorkspace = functions.https.onCall(
    reportedHttpCallFunction({ name: 'addRepoToWorkspace' }, async (logger, data, context) => {
        try {
            const { repoId, workspaceId, isPrivate } = data;

            commonUtils.assertRequestAuthenticated(context);
            await commonUtils.assertWorkspaceAdmin(context, workspaceId);

            const workspaceRef = await commonUtils.getWorkspace(workspaceId);
            const workspace = workspaceRef.data();
            if (workspace.repositories.length && workspace.repositories.includes(repoId)) {
                logger.error(`Attempted to add repo ${repoId} to workspace ${workspaceId}, but it's already there`);
                return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
            }

            const isAllowedToAddRepo = await validateAddRepoToWorkspace({ context, workspaceId, isPrivate });

            if (!isAllowedToAddRepo) {
                logger.error(`Attempted to add repo ${repoId} to workspace ${workspaceId}, but no more repos can be added`);
                return { status: 'error', code: StatusCodes.PAYMENT_REQUIRED };
            }

            const isRepoExistsInAnotherWorkspace = await db
                .collection('workspaces')
                .where('repositories', 'array-contains', repoId)
                .get();

            if (isPrivate && isRepoExistsInAnotherWorkspace.docs.length) {
                logger.info(`Cannot add repo ${repoId} to workspace ${workspaceId}, it already exists on another workspace`);
                return { status: 'error', code: StatusCodes.FORBIDDEN };
            }

            await db
                .collection(`workspaces`)
                .doc(workspaceId)
                .update({
                    modified: FieldValue.serverTimestamp(),
                    repositories: [...workspace.repositories, repoId],
                });

            logger.info(`Repo ${repoId} added to workspace ${workspaceId}`);
            return { status: 'success', code: StatusCodes.OK };
        } catch (error) {
            logger.error(`Error: ${error}`);
            return { status: 'error', code: StatusCodes.INTERNAL_SERVER_ERROR };
        }
    })
);

async function validateAddRepoToWorkspace({ context, workspaceId, isPrivate }) {
    const logger = getLogger({ context, module: 'validateAddRepoToWorkspace' });
    const workspaceRef = await commonUtils.getWorkspace(workspaceId);
    const workspace = workspaceRef.data();

    let privateRepoLimit = DEFAULT_PRIVATE_REPO_LIMIT;
    const billedWorkspaceRef = await db.collection(`billing_workspaces`).doc(workspaceId).get();

    if (billedWorkspaceRef.exists) {
        const billingAccountId = billedWorkspaceRef.data().billing_account_id;
        const billingAccountRef = await db.collection(`billing_accounts`).doc(billingAccountId).get();

        if (billingAccountRef.exists) {
            privateRepoLimit = billingAccountRef.data().private_repos_limit;
        }
    }

    let workspacePrivateRepos = 0;
    if (workspace.repositories.length) {
        const workspaceReposData = await Promise.all(
            workspace.repositories.map((repoId) => db.collection('repositories').doc(repoId).get())
        );
        workspacePrivateRepos = workspaceReposData.filter((repo) => repo.data().is_private !== false).length;
    }

    logger.info(
        `Workspace ${workspaceId} is on ${workspace.license} plan, and has ${workspacePrivateRepos} private repos out of ${workspace.repositories.length} total repos, with a limit of ${privateRepoLimit} private repos`
    );

    if (workspace.license !== 'pro' && isPrivate && workspacePrivateRepos >= privateRepoLimit) {
        logger.debug(`Cannot add any more repos to workspace ${workspaceId}, payment required`);
        return false;
    }

    logger.debug(`At least one more repo can be added to workspace ${workspaceId}`);
    return true;
}

export const getWorkspaceSwimmersStatuses = functions.runWith({ timeoutSeconds: 120, memory: '2GB' }).https.onCall(
    reportedHttpCallFunction({ name: 'getWorkspaceSwimmersStatuses' }, async (logger, data, context) => {
        try {
            const swimmersStatuses = [];
            const { workspaceId } = data;

            commonUtils.assertRequestAuthenticated(context);
            await commonUtils.assertWorkspaceAdmin(context, workspaceId);

            const workspace = await commonUtils.getWorkspace(workspaceId); // Asserts and throws if the workspace doesn't exist
            const workspaceUsersResponse = await workspace.ref.collection('workspace_users').get();
            const workspaceUsersNames = {};
            workspaceUsersResponse.forEach((user) => {
                workspaceUsersNames[user.id] = user.data().name;
            });

            const repos = await db.collection(`repositories`).get();
            await Promise.all(
                repos.docs.map(async (repo) => {
                    const swimmers = await db.collection(`repositories`).doc(repo.id).collection('swimmers').get();
                    if (!swimmers.empty) {
                        const swimmersUids = [];
                        swimmers.docs.forEach((user) => {
                            if (Object.keys(workspaceUsersNames).includes(user.id)) {
                                swimmersUids.push(user.id);
                            }
                        });
                        await Promise.all(
                            swimmersUids.map(async (swimmerUid) => {
                                logger.debug(`Fetching swimms_status for repo ${repo.id} for user ${swimmerUid}`);
                                const swimmerStatusCollection = await db
                                    .collection(`repositories`)
                                    .doc(repo.id)
                                    .collection('swimmers')
                                    .doc(swimmerUid)
                                    .collection('swimms_status')
                                    .get();
                                swimmerStatusCollection.docs.forEach((swimmStatus) => {
                                    swimmersStatuses.push({
                                        repoId: repo.id,
                                        userId: swimmerUid,
                                        swimmId: swimmStatus.id,
                                        swimmStatus: swimmStatus.data(),
                                        userName: workspaceUsersNames[swimmerUid] || 'User',
                                    });
                                });
                            })
                        );
                    }
                })
            );
            return { status: 'success', swimmersStatuses };
        } catch (error) {
            logger.error(`Error: ${error}`);
            const errorStatusCode = resourcesErrors[error.code]
                ? resourcesErrors[error.code].statusCode
                : resourcesErrors.DEFAULT_ERROR.statusCode;
            return { status: 'error', code: errorStatusCode, message: 'Getting swimmers statuses failed' };
        }
    })
);

export const scheduledMailer = functions.pubsub.schedule('every 24 hours').onRun(
    reportedScheduledFunction({ name: 'scheduledMailer' }, async (logger) => {
        if (!isProduction) {
            logger.debug(`Not a production environment, aborting`);
            return;
        }
        await dailyMailHandler(admin, db);
    })
);

export const newDocMailer = functions.firestore.document(`repositories/{repoId}/swimms/{docId}`).onCreate(
    reportedFirestoreFunction({ name: 'newDocMailer' }, async (logger, snapshot, context) => {
        try {
            if (!isProduction) {
                logger.debug(`Not a production environment, aborting`);
                return;
            }
            const docId = snapshot.id;
            const { repoId } = context.params;
            await newDoc(admin, db, docId, repoId);
        } catch (error) {
            logger.error(`Error: ${error}`);
        }
    })
);

async function emailWorkspaceAdmins({ workspaceId, templateId, templateData, context = {} }) {
    const logger = getLogger({ context, module: 'emailWorkspaceAdmins' });
    logger.info(`Received email admins request for template ${templateId}`);

    const workspaceAdminsRef = await db.collection('workspaces').doc(workspaceId).collection('workspace_admins').get();
    const workspaceAdmins = workspaceAdminsRef.docs.map((doc) => doc.data().id);
    const workspaceAdminsEmails = await getUsersEmails(workspaceAdmins);

    await Promise.all(
        workspaceAdminsEmails.map(async (email) => {
            const emailMessage = {
                from: {
                    name: 'Swimm',
                    email: 'donotreply@swimm.io',
                },
                templateId,
                dynamic_template_data: {
                    ...templateData,
                },
            };

            const msg = { to: email, ...emailMessage };
            return sendSGMail({ msg, context, purpose: 'notify admin - request invite to workspace' });
        })
    );
}

import { useAnalytics } from '@/common/composables/useAnalytics';
import { appLinks, navigate } from '@/common/mixins/helpers';
import tokenizer from '@/common/mixins/tokenizer';
import { reportAutosyncedShownInSwm } from '@/common/utils/doc-utils/doc-utils';
import { productEvents } from '@/common/utils/product-events-reporters';
import { SymbolBus } from '@/common/utils/symbolBus';
import { loadProcessedDraftById } from 'Adapters/load';
import { draftExists } from '@/adapters-common/load_common';
import { commitToBranch, createFileAndRemoteBranch, createPR, saveSwmDraft } from 'Adapters/save';
import { deleteSWMDraft } from 'Adapters/delete';
import {
    PJSON_VERSION,
    SUCCESS_RETURN_CODE,
    SWIMM_FILE_TYPES,
    SWM_SCHEMA_VERSION,
    UNIT_PLAY_MODES,
} from 'Shared/config';
import { SWIMM_EVENTS } from 'Shared/event-logger/swimm-events';
import { objectUtils } from 'Shared/objectUtils';
import state from 'Shared/shared-local-state';
import { cleanSwmRuntimeKeys, cleanSymbolsRuntimeKey } from 'Shared/utils/swm-common-functions';
import {
    filterSwmCells,
    filterSwmSymbols,
    getSwmLinksRepos,
    injectInlineImages,
    markInlineImagesAsNew,
    swmdFileName,
} from 'Shared/utils/swm-utils';
import {
    getSymbolLinkRegex,
    getSymbolPathRegex,
    getSymbolTextRegex,
    getTextPlaceholderRegex,
} from 'Shared/utils/symbols-utils';
import swal from 'sweetalert';
import {
    ApplicabilityStatus,
    HunkChangeLineType,
    SwmCellType,
    SwmSymbolType,
    getLineTypeByMarker,
} from 'Swimmagic/swimm-patch-common';
import { v4 as uuidv4 } from 'uuid';
import { shortUuid } from '@/common/utils/helpers';
import Vue from 'vue';
import { mapActions, mapGetters, mapState } from 'vuex';
import arrayUtils from 'Shared/arrayUtils';
import { SWAL_CONTACT_US_CONTENT } from '../utils/common-definitions';
import { logEvent } from './event-logger';
import { initData } from './storeModulesWrapper';
import * as config from 'Shared/config';
import routing from '@/common/mixins/routing';
import { autosyncUnit } from 'Swimmagic/autosync';
import { encodeString } from 'Shared/utils/string-utils';
import gitwrapper from 'Shared/git-utils/remote/gitwrapper';
import { useToastNotification } from '@/modules/common/composables/notifications';
import { addDocContribution } from '@/modules/doc-contributions/services/doc-contributors-utils';

const unitForm = {
    mixins: [logEvent, appLinks, navigate, tokenizer, initData, routing],
    data() {
        return {
            swm: {
                name: '',
                meta: { file_blobs: {} },
                content: [],
                symbols: {},
            },
            tempDeletedSymbols: {},
            originalSwmForAutosync: null,
            originalSwmFromFile: null,
            isNewUnit: !this.$route.params.unitId,
            isDoc: false,
            isDraft: false,
            saving: false,
            isRunningAutosync: false,
            hintsEdited: false,
            dodEdited: false,
            activeBranch: '',
            hasChanged: false,
            selectedTabIndex: 0,
            hintPrefixes: [
                "Don't forget to",
                'Look at file',
                'Did you try to',
                'Look at a pattern that is similar such as',
                'Visit the following link',
            ],
            dodPrefixes: ['In this exercise you should', 'Please implement', 'Make the tests pass'],
            isUnitCreatedFromCLI: this.$route.query.source === 'cli',
            isUnitCreatedFromInsights: this.$route.query.source === 'insights',
            isUnitDuplicate: !!this.$route.query.unitToDuplicateId,
            commitSHAModal: {
                show: false,
                heading: 'Commit SHA',
            },
            snippetEditorModal: {
                show: false,
                heading: 'SNIPPET STUDIO',
                lastSelectedFilePath: '',
            },
            currentEditedHunk: null,
            addSnippetIndex: 1,
            saveMethod: 'Save & Commit',
            saveOptions: {
                saveCommit: 'Save & Commit',
                saveOnly: 'Save Only',
            },
            tokens: {},
            loadingCreatingPR: false,
            loadingPushingToBranch: false,
            toastDeleteMessage: {
                [SwmCellType.Text]: 'Text block',
                [SwmCellType.Snippet]: 'Snippet',
                [SwmCellType.Image]: 'Image',
                [SwmCellType.SnippetPlaceholder]: 'Snippet placeholder',
                [SwmCellType.Table]: 'Table',
            },
            isSWMD: false,
            debouncedDraftSaver: null,
            savingDraft: false,
            isFirstDoc: true,
            indexOfReview: -1,
            currentIndex: -1,
            isSavingToNewBranch: false,
        };
    },
    setup(_, context) {
        const analytics = useAnalytics();
        const { showToast } = useToastNotification(context);
        return { analytics, showToast };
    },
    created() {
        SymbolBus.$on('applicability-changed', this.symbolApplicabilityChanged);
        SymbolBus.$on('symbol-deleted', this.updateSymbol);
        SymbolBus.$on('symbol-created', this.symbolCreated);
        SymbolBus.$on('text-placeholder-changed', this.changeTextPlaceholderValue);
        if (this.$route.query.path) {
            this.snippetEditorModal.lastSelectedFilePath = this.$route.query.path;
            // Remove path query param from URL & router
            let query = Object.assign({}, this.$route.query);
            delete query.path;
            this.$router.replace({ query });
        }
        this.$watch('reviewData', () => {
            if (this.reviewData.length === 0) {
                this.clearAllReviewHighlights();
                this.currentIndex = -1;
                this.indexOfReview = -1;
            }
        });
    },
    beforeDestroy() {
        SymbolBus.$off('applicability-changed', this.symbolApplicabilityChanged);
        SymbolBus.$off('symbol-deleted', this.updateSymbol);
        SymbolBus.$off('text-placeholder-changed', this.changeTextPlaceholderValue);
    },
    computed: {
        ...mapState('auth', ['user']),
        ...mapGetters(['getPreviousRoute']),
        ...mapGetters('topbar', ['getReviewData']),
        ...mapGetters('database', [
            'db_getSwimm',
            'db_getRepoMetadata',
            'db_getSwimms',
            'db_getPlaylist',
            'db_getPlaylists',
        ]),
        ...mapGetters('filesystem', [
            'fs_isUnitFileInRepoPath',
            'fs_getSwmdFileNameInRepo',
            'fs_getRepoLocalFilesLists',
            'fs_getUnitFromLocalRepo',
        ]),
        isEditable() {
            return !this.isRunningAutosync && !this.isPerformingSave;
        },
        isPerformingSave() {
            return this.saving || this.loadingPushingToBranch || this.loadingCreatingPR;
        },
        canSaveGeneric() {
            return (
                !this.isRunningAutosync &&
                (this.hasAutosyncableSymbols || this.hasChanged) &&
                this.swm.name.trim() !== '' &&
                !this.isContentEmpty &&
                (objectUtils.isEmpty(this.swm.symbols) || this.isAllSymbolsValidForSaving) &&
                (!this.hasDiff || this.isAllHunksValidForSaving) &&
                !this.hasSomeUnavailableLinksInSwm
            );
        },
        isContentEmpty() {
            for (const cell of this.swm.content) {
                if (
                    cell.type === SwmCellType.Snippet ||
                    (cell.type === SwmCellType.Text && cell.text.length > 0) ||
                    (cell.type === SwmCellType.Table && cell.headers.length > 0) ||
                    cell.type === SwmCellType.Image
                ) {
                    return false;
                }
            }
            return true;
        },
        localFileType() {
            return !this.isDoc
                ? config.SWIMM_FILE_TYPES.SWM
                : this.isSWMD
                    ? config.SWIMM_FILE_TYPES.SWMD
                    : config.SWIMM_FILE_TYPES.SWM;
        },
        reviewData() {
            return this.getReviewData;
        },
        hasEmptyTest() {
            return arrayUtils.hasEmtpyValue(this.swm.task.tests);
        },
        hasEmptyHint() {
            return arrayUtils.hasEmtpyValue(this.swm.task.hints);
        },
        hasDiff() {
            return this.unitHasDiff(this.swm);
        },
        commitMessage() {
            const resourceName = this.isDoc ? `document` : 'exercise';
            return `docs(swimm): ${
                this.swm.id
                    ? `update ${resourceName} ${this.swm.name} ${this.swm.id}`
                    : `create ${resourceName} ${this.swm.name}`
            }`;
        },
        isAllHunksValidForSaving() {
            if (!this.unitHasDiff(this.swm)) {
                return false;
            }
            for (const cell of this.swm.content) {
                if (cell.type === SwmCellType.Snippet) {
                    if (cell.applicability && cell.applicability !== ApplicabilityStatus.Verified) {
                        return false;
                    }
                }
            }
            return true;
        },
        isAllSymbolsValidForSaving() {
            return !this.hasOutdatedSymbols;
        },
        isAllSymbolsValid() {
            return !this.isSwmContainingSymbolsByStatus({
                applicabilityStatusTypes: [ApplicabilityStatus.Outdated, ApplicabilityStatus.Autosyncable],
            });
        },
        hasAutosyncableSymbols() {
            return this.isSwmContainingSymbolsByStatus({ applicabilityStatusTypes: [ApplicabilityStatus.Autosyncable] });
        },
        hasOutdatedSymbols() {
            return this.isSwmContainingSymbolsByStatus({ applicabilityStatusTypes: [ApplicabilityStatus.Outdated] });
        },
        snippets() {
            return filterSwmCells(this.swm, SwmCellType.Snippet);
        },
        snippetsCount() {
            return this.snippets.length;
        },
        snippetsAsOneString() {
            const snippetStrings = [];
            for (const cell of this.snippets) {
                snippetStrings.push({ path: cell.path, snippetString: cell.lines.join('\n') });
            }
            return snippetStrings;
        },
        shouldExportSwmToMD() {
            const repo = this.db_getRepoMetadata(this.$route.params.repoId);
            const shouldExportToMdConfig = repo.integrations ? !!repo.integrations.md_export_upon_save : false;
            return this.isDoc && shouldExportToMdConfig;
        },
        swimmLinksInSwm() {
            if (!this.swm.symbols) {
                return [];
            }
            const swmString = JSON.stringify(this.swm.content.map((content) => content.comments || content.text));
            return Object.entries(this.swm.symbols)
                .filter(
                    ([key, value]) =>
                        value.type === SwmSymbolType.LINK &&
                        swmString.match(new RegExp(`\\[\\[sym-link:\\(${key}\\).*?\\]\\]`, 'g'))
                )
                .map(([key, value]) => ({ data: value, id: key }));
        },
        hasSomeUnavailableLinksInSwm() {
            return this.swimmLinksInSwm.some(
                (link) =>
                    !this.loadingLinkRepo(link.data.repoId) &&
                    (!this.isSwimmIdInDB(link.data.swimmId, link.data.swimmType, link.data.repoId) ||
                        !this.fs_isUnitFileInRepoPath(link.data.swimmId, link.data.repoId))
            );
        },
        swimmFromDb() {
            return this.db_getSwimm(this.$route.params.repoId, this.$route.params.unitId);
        },
    },
    methods: {
        ...mapActions(['updatePreventNavigation']),
        ...mapActions('database', [
            'saveResourceInFirebaseDocument',
            'fetchRepoChildren',
            'fetchRepository',
            'refreshContributors',
        ]),
        ...mapActions('filesystem', [
            'loadLocalSwmFile',
            'setSelectedFolderTreePath',
            'setSwimmToRepoSwmsList',
            'getRepoSwmsLists',
        ]),
        ...mapActions('topbar', ['setReviewData', 'setHasSnippetsToReview']),
        ...mapActions('generatedDocs', { repoIgnoreGeneratedDocument: 'repoIgnoreDocument' }),
        saveUpdatedComments(commentsEvent, cellIndex) {
            try {
                const { comments } = commentsEvent;
                this.swm.content[cellIndex].comments = [...comments];
                this.updateReviewData();
            } catch (error) {
                this.$logger.error(`could not update hunk comments. ${error.toString()}`, { service: 'unit-form' });
            }
        },
        updateTableHeaders(headersEvent, cellIndex) {
            this.updateTable({ newData: headersEvent.data, cellIndex, isHeaders: true });
        },
        updateTableData(dataEvent, cellIndex) {
            this.updateTable({ newData: dataEvent.data, cellIndex, isHeaders: false });
        },
        updateTable({ newData, cellIndex, isHeaders }) {
            try {
                if (isHeaders) {
                    this.swm.content[cellIndex].headers = newData;
                } else {
                    this.swm.content[cellIndex].table = newData;
                }
                this.updateReviewData();
            } catch (error) {
                this.$logger.error(`could not update table ${isHeaders ? 'headers' : 'data'}. ${error.toString()}`, {
                    service: 'unit-form',
                });
            }
        },
        addTableCell(cellIndex) {
            const newTableCell = {
                type: SwmCellType.Table,
                headers: ['', ''],
                table: [['', '']],
                tempId: uuidv4(),
            };
            this.addCellInSpecificIndex(newTableCell, cellIndex);
            this.analytics.track(productEvents.TABLE_ADDED, {}, { addRouteParams: true });
        },
        getAllInvalidCells() {
            const invalidCells = [];
            invalidCells.push(...this.getAllInvalidHunks());
            invalidCells.push(...this.getUnavailableLinksInSwm());
            invalidCells.push(...this.getReviewSymbols());
            return this.sortSymbolCells(invalidCells);
        },
        getAllInvalidHunks() {
            if (!this.unitHasDiff(this.swm)) {
                return [];
            }
            return this.swm.content.filter(
                (cell) =>
                    cell.type === SwmCellType.Snippet && cell.applicability && cell.applicability !== ApplicabilityStatus.Verified
            );
        },
        getUnavailableLinksInSwm() {
            return this.swimmLinksInSwm
                .filter(
                    (link) =>
                        !this.loadingLinkRepo(link.data.repoId) &&
                        (!this.isSwimmIdInDB(link.data.swimmId, link.data.swimmType, link.data.repoId) ||
                            !this.fs_isUnitFileInRepoPath(link.data.swimmId, link.data.repoId))
                )
                .map((link) => {
                    return {
                        ...link.data,
                        tempId: this.getCellTempIdFromSymbol(link.id, SwmSymbolType.LINK),
                    };
                });
        },
        getReviewSymbols() {
            return this.getSwmContainingSymbolsByStatus({
                applicabilityStatusTypes: [ApplicabilityStatus.Outdated, ApplicabilityStatus.Autosyncable],
            });
        },
        symbolCreated(node) {
            if (this.tempDeletedSymbols[node.attrs.id]) {
                Vue.set(this.swm.symbols, node.attrs.id, this.tempDeletedSymbols[node.attrs.id]);
                this.updateReviewData();
            }
        },
        changeTextPlaceholderValue(placeholderId, inputValue) {
            this.swm.symbols[placeholderId].value = inputValue;
        },
        moveCellUp(cellIndex) {
            this.moveCell({ down: false, cellIndex });
        },
        moveCellDown(cellIndex) {
            this.moveCell({ down: true, cellIndex });
        },
        moveCell({ down, cellIndex }) {
            if (this.isPerformingSave) {
                return;
            }

            const index = down ? 1 : -1;
            const switchedCellIndex = cellIndex + index;
            const cell = this.swm.content.splice(cellIndex, 1)[0];
            this.swm.content.splice(cellIndex + index, 0, cell);
            this.updateReviewData();
            if (cellIndex === this.currentIndex) {
                // If the moved cell is the highlighted one
                this.moveFocusedCellPosition({ down });
            } else if (switchedCellIndex === this.currentIndex) {
                // If the switched cell (the affected cell) was highlighted
                this.moveFocusedCellPosition({ down: !down });
            }
        },
        moveFocusedCellPosition({ down }) {
            const index = down ? 1 : -1;
            this.indexOfReview = this.indexOfReview + index;
            this.goToCell({ cellIndex: this.currentIndex + index, indexToRemove: this.currentIndex });
            this.currentIndex = this.currentIndex + index;
        },
        focusedNextStepWhenSnippetIsFixed(hunkIndex) {
            if (this.currentIndex >= 0 && hunkIndex === this.currentIndex) {
                //checks if its the last cell in general or if its the last broken cell, go to the previous step
                if (this.currentIndex === this.swm.content.length - 1 || this.indexOfReview === this.reviewData.length) {
                    this.goToPreviousReviewStep();
                    return;
                }
                this.indexOfReview--;

                this.goToNextReviewStep();
            }
        },
        async editSnippet(editHunk) {
            const { file, hunkIndex, acceptAutosyncedHunk } = editHunk;
            if (acceptAutosyncedHunk) {
                Vue.set(this.swm.content[hunkIndex], 'applicability', ApplicabilityStatus.Verified);
                this.logUpdateHunkChanges({ action: 'acceptAutosynced' });
                this.updateReviewData();
                if (this.reviewData.length === 0) {
                    return;
                }
                this.focusedNextStepWhenSnippetIsFixed(hunkIndex);
                return;
            }
            const cell = this.swm.content[hunkIndex];
            this.currentEditedHunk = {
                hunk: cell.type === SwmCellType.SnippetPlaceholder ? null : cell,
                hunkIndex: hunkIndex,
            };
            if (file) {
                this.snippetEditorModal.lastSelectedFilePath = file;
            }
            this.logUpdateHunkChanges({ action: 'update' });

            await this.toggleSnippetStudioModal({ open: true, index: hunkIndex + 1 });
            this.updateReviewData();
            this.focusedNextStepWhenSnippetIsFixed(hunkIndex);
        },
        clearAllReviewHighlights() {
            this.$nextTick(() => {
                const elements = document.getElementsByClassName('focusOnReviewCell');
                if (elements) {
                    for (const element of elements) {
                        element.classList.remove('focusOnReviewCell');
                    }
                }
            });
        },
        discardInEditHunk(deleteHunkEvent) {
            const { hunkIndex } = deleteHunkEvent;
            this.deleteCell(hunkIndex);
            this.currentEditedHunk = null;
            this.setSelectedFolderTreePath({ path: '', repoId: this.$route.params.repoId });
        },
        logUpdateHunkChanges({ action, applicability }) {
            try {
                let srcName = this.swm.name;
                let srcId = this.swm.id;
                if (!this.swm.id && this.isNewUnit) {
                    srcId = 'new-document';
                } else if (this.isUnitDuplicate) {
                    srcId = `duplicated_doc_${this.$route.query.unitToDuplicateId}`;
                }

                if (action === 'acceptAutosynced') {
                    this.logEvent({
                        swimmEventCode: SWIMM_EVENTS.AUTOSYNC_HUNK_ACCEPTED.code,
                        repoId: this.$route.params.repoId,
                        repoName: this.db_getRepoMetadata(this.$route.params.repoId).name || '',
                        srcId: srcId,
                        srcName: srcName,
                    });
                    return;
                }

                const hunkApplicability = applicability || ApplicabilityStatus.Verified;

                if (hunkApplicability !== ApplicabilityStatus.Verified) {
                    let swimmEvent;
                    if (action === 'update') {
                        swimmEvent =
                            (hunkApplicability === ApplicabilityStatus.Autosyncable && SWIMM_EVENTS.AUTOSYNCED_HUNK_RESELECTED) ||
                            SWIMM_EVENTS.OUTDATED_HUNK_RESELECTED;
                    } else {
                        swimmEvent = SWIMM_EVENTS.OUTDATED_HUNK_DELETED;
                    }
                    this.logEvent({
                        swimmEventCode: swimmEvent.code,
                        repoId: this.$route.params.repoId,
                        repoName: this.db_getRepoMetadata(this.$route.params.repoId).name || '',
                        srcId: srcId,
                        srcName: srcName,
                    });
                }
            } catch (error) {
                this.$logger.error(`could not send event log. Details: ${error.toString()}`, { service: 'unit-form' });
            }
        },
        handleDelete(cellIndex) {
            if (cellIndex === 0 && this.swm.content.length === 1) {
                // don't delete the only block.
                return;
            }

            // if we are focused on review, we want to focus the review back (handled in the handleReviewDeleted)
            if (this.currentIndex === -1) {
                if (cellIndex !== 0) {
                    const nearestItem = cellIndex - 1;
                    this.focusOnCell(nearestItem);
                } else {
                    // if first cell - focus on title)
                    this.focusOnTitle();
                }
            }

            this.deleteCell(cellIndex);
        },
        deleteCell(cellIndex) {
            if (this.isPerformingSave) {
                return;
            }

            // keep original data for recover
            const deletedCell = this.swm.content.splice(cellIndex, 1)[0];
            this.addSnippetIndex = cellIndex;
            this.handleReviewDeleted(deletedCell, cellIndex);
            this.removeDeletedFileTokens(deletedCell.path);

            this.logUpdateHunkChanges({ action: 'delete', applicability: deletedCell.applicability });
            if (deletedCell.type !== SwmCellType.Text) {
                this.showToast(`${this.toastDeleteMessage[deletedCell.type]} deleted`, {
                    action: {
                        text: 'Undo',
                        onClick: (e, toastObject) => {
                            toastObject.goAway(0);
                            this.addCellInSpecificIndex(deletedCell, cellIndex);
                        },
                    },
                });
            }
            // if the last cell was snippet and it was deleted - add an empty text block
            // can be true only in docs
            if (this.swm.content.length === 0) {
                this.swm.content.push({ type: SwmCellType.Text, text: '' });
                this.focusOnCell(0);
            }

            this.setHasSnippetsToReview({ hasSnippetsToReview: this.hasDiff });
            this.updateReviewData();
        },
        collapseHunksInSwm(payload) {
            const { index, shouldCollapse } = payload;
            Vue.set(this.swm.content[index], 'collapsed', shouldCollapse);
        },
        handleReviewDeleted(deletedCell, removedIndex) {
            const isImpactedCellPartOfReviewData = this.reviewData.some(
                (reviewDataCell) => reviewDataCell.tempId === deletedCell.tempId
            );
            this.updateReviewData();

            // if we removed a non-review cell, focus back to highlighted review
            if (!isImpactedCellPartOfReviewData) {
                if (this.reviewData.length > 0 && this.currentIndex !== -1) {
                    if (removedIndex < this.currentIndex) {
                        this.goToNextReviewStep();
                    } else {
                        this.goToPreviousReviewStep();
                    }
                }
                return;
            }
            // the highlighted is the removed
            if (this.currentIndex === removedIndex) {
                // removed is not last
                if (this.currentIndex < this.swm.content.length && this.indexOfReview < this.reviewData.length) {
                    if (this.indexOfReview !== -1) {
                        this.indexOfReview--;
                    }
                    if (this.currentIndex !== -1) {
                        this.currentIndex--;
                    }
                    this.goToNextReviewStep();
                } else if (this.currentIndex - 1 > -1) {
                    // if last but not first
                    this.currentIndex--;
                    this.goToCell({ cellIndex: this.currentIndex });
                } else {
                    // if last and first
                    this.currentIndex--;
                }
            } else {
                // highlighted is not removed
                if (removedIndex < this.currentIndex) {
                    // removed is above highlighted
                    if (this.indexOfReview !== -1) {
                        this.indexOfReview--;
                    }
                    if (this.currentIndex !== -1) {
                        this.currentIndex--;
                    }
                    this.goToCell({ cellIndex: this.currentIndex, indexToRemove: this.currentIndex - 1 });
                }
            }
        },
        handleDragContent() {
            this.updateReviewData();
            this.indexOfReview = -1;
            this.currentIndex = -1;
            this.goToNextReviewStep();
        },
        deleteFileSnippets(fileName) {
            const beforeContent = [...this.swm.content];
            this.swm.content = this.swm.content.filter((cell) => !cell.path || cell.path !== fileName);

            this.removeDeletedFileTokens(fileName);
            // if the last cell was snippet and it was deleted - add an empty text block
            // can be true only in docs
            if (this.swm.content.length === 0) {
                this.swm.content.push({ type: SwmCellType.Text, text: '' });
            }

            this.showToast(`Snippets for file ${fileName} deleted`, {
                action: {
                    text: 'Undo',
                    onClick: (e, toastObject) => {
                        toastObject.goAway(0);
                        this.swm.content = beforeContent;
                    },
                },
            });
            this.setHasSnippetsToReview({ hasSnippetsToReview: this.hasDiff });
            this.updateReviewData();
        },
        addCellInSpecificIndex(cell, index) {
            this.swm.content.splice(index, 0, cell);
            this.updateReviewData();

            if (![SwmCellType.Snippet, SwmCellType.SnippetPlaceholder].includes(cell.type)) {
                this.focusOnCell(index);
            } else {
                this.setHasSnippetsToReview({ hasSnippetsToReview: true });
            }
        },
        addTest() {
            if (!this.hasEmptyTest) {
                this.swm.task.tests.push('');
            }
        },
        removeTest(index) {
            this.swm.task.tests.splice(index, 1);
        },
        addHint() {
            if (!this.hasEmptyHint) {
                this.swm.task.hints.push('');
                this.hintsEdited = true;
            }
        },
        removeHint(index) {
            this.swm.task.hints.splice(index, 1);
        },
        async getActiveBranchText() {
            return 'Branch';
        },
        addSnippets({ SnippetSelectEvent, snippets, keepFilePath = false }) {
            if (this.currentEditedHunk) {
                Vue.set(this.swm.content[SnippetSelectEvent.hunkIndex], 'type', SwmCellType.Snippet);
                Vue.set(this.swm.content[SnippetSelectEvent.hunkIndex], 'lines', SnippetSelectEvent.lines);
                Vue.set(this.swm.content[SnippetSelectEvent.hunkIndex], 'firstLineNumber', SnippetSelectEvent.firstLineNumber);
                Vue.set(this.swm.content[SnippetSelectEvent.hunkIndex], 'path', SnippetSelectEvent.path);
                Vue.set(this.swm.content[SnippetSelectEvent.hunkIndex], 'applicability', ApplicabilityStatus.Verified);
                this.addTokenFromSnippet(SnippetSelectEvent);
                this.currentEditedHunk = null;
            } else {
                const snippetsToAdd = SnippetSelectEvent ? [SnippetSelectEvent] : snippets;
                for (const snippetToAdd of snippetsToAdd) {
                    // new snippet
                    const snippet = {
                        type: SwmCellType.Snippet,
                        lines: snippetToAdd.lines,
                        firstLineNumber: snippetToAdd.firstLineNumber,
                        path: snippetToAdd.path,
                        comments: [],
                    };
                    if (snippetToAdd.patchType) {
                        snippet.patchType = snippetToAdd.patchType;
                    }
                    // adding the snippet in the requested index and increasing the index for the next one (add another)
                    this.addCellInSpecificIndex(snippet, this.addSnippetIndex);
                    this.addSnippetIndex++;

                    // update file blobs
                    if (!this.swm.meta.file_blobs[snippet.path]) {
                        Vue.set(this.swm.meta.file_blobs, snippet.path, '');
                    }
                    if (keepFilePath) {
                        this.snippetEditorModal.lastSelectedFilePath = snippet.path;
                    }
                    this.addTokenFromSnippet(snippet);
                }
            }
            this.updateReviewData();
        },
        async getPreferredSavingMethod() {
            const selectedSavingMethod = await state.get({
                key: 'preferred_save_method',
                defaultValue: this.saveOptions.saveCommit,
                repoId: this.$route.params.repoId,
            });
            this.saveMethod = Object.values(this.saveOptions).includes(selectedSavingMethod)
                ? selectedSavingMethod
                : this.saveOptions.saveCommit;
        },
        async saveToDbAndPrepareForFileSave() {
            const unitId = await this.saveSwimmDocInDatabase();
            let swmContent = this.swm.content;
            // Prevent saving of empty text cells for docs
            if (this.isDoc) {
                swmContent = this.swm.content.filter((cell) => cell.type !== SwmCellType.Text || cell.text.trim() !== '');
            }
            swmContent = objectUtils.deepClone(swmContent);
            let unitToSave = {
                id: unitId,
                name: this.swm.name,
                task: this.swm.task,
                content: swmContent,
                symbols: this.swm.symbols,
            };
            return await this.prepareUnitBeforeSave(unitToSave);
        },
        async pushToBranch(pushData) {
            // Clear draft timers
            clearTimeout(this.debouncedDraftSaver);

            if (this.loadingCreatingPR || this.loadingPushingToBranch) {
                return;
            }
            this.loadingPushingToBranch = true;
            let unitToSave;
            try {
                unitToSave = await this.saveToDbAndPrepareForFileSave();
            } catch (error) {
                this.loadingPushingToBranch = false;
                this.$logger.error(`Failed to save doc in DB: ${error}`, { module: 'unit-form' });
                await swal({ title: 'Failed to save doc', content: SWAL_CONTACT_US_CONTENT() });
                return;
            }
            const unitId = unitToSave.id;
            const response = await commitToBranch({
                swmFile: unitToSave,
                originalSwmFile: this.originalSwmFromFile,
                repoId: this.$route.params.repoId,
                shouldExportToMD: this.shouldExportSwmToMD,
                commitMessage: pushData.commitMessage,
                branch: pushData.branch,
                swmdFileNameBeforeEdit: this.fs_getSwmdFileNameInRepo(this.$route.params.repoId, unitId),
                isNew: this.isNewUnit,
            });
            if (response.code === SUCCESS_RETURN_CODE) {
                const fileType = this.localFileType;
                const branch = await this.getCurrentOrDefaultBranch(this.$route.params.repoId);
                await this.setSwimmToRepoSwimmList(unitToSave);
                const fileName =
                    this.localFileType === SWIMM_FILE_TYPES.SWMD
                        ? this.fs_getSwmdFileNameInRepo(this.$route.params.repoId, unitId)
                        : unitToSave.id;
                await addDocContribution({
                    user: this.user,
                    repoId: this.$route.params.repoId,
                    docId: unitId,
                    method: 'commit',
                    branch: pushData.branch,
                });
                await this.loadLocalSwmFile({
                    fileName,
                    reload: true,
                    repoId: this.$route.params.repoId,
                    shouldAutoSync: false,
                    type: fileType,
                    branch,
                });
                await this.afterSuccessfulSave({ pushData, unitId, method: 'commit' });
                if (this.isNewUnit) {
                    this.navigateToRepoPage({ highlightedUnitId: unitId }, branch);
                } else {
                    this.routeBackFromDoc();
                }
            } else {
                await swal({ title: 'Failed to push changes', content: SWAL_CONTACT_US_CONTENT() });
            }
            this.loadingPushingToBranch = false;
        },
        async openRemoteBranch(pushData) {
            // Clear draft timers
            clearTimeout(this.debouncedDraftSaver);

            if (this.loadingCreatingPR || this.loadingPushingToBranch) {
                return;
            }
            // Using same loader for creating PR since it's just a checkbox difference.
            this.loadingCreatingPR = true;

            let unitToSave;
            try {
                unitToSave = await this.saveToDbAndPrepareForFileSave();
            } catch (error) {
                this.loadingCreatingPR = false;
                this.$logger.error(`Failed to save doc in DB: ${error}`, { module: 'unit-form' });
                await swal({ title: 'Failed to save doc', content: SWAL_CONTACT_US_CONTENT() });
                return;
            }
            const unitId = unitToSave.id;

            const response = await createFileAndRemoteBranch({
                swmFile: unitToSave,
                originalSwmFile: this.originalSwmFromFile,
                repoId: this.$route.params.repoId,
                shouldExportToMD: this.shouldExportSwmToMD,
                commitMessage: pushData.commitMessage,
                branch: pushData.branch,
                prBranch: pushData.prBranch,
                swmdFileNameBeforeEdit: this.fs_getSwmdFileNameInRepo(this.$route.params.repoId, unitId),
                isNew: this.isNewUnit,
            });
            if (response.code === SUCCESS_RETURN_CODE) {
                await addDocContribution({
                    user: this.user,
                    repoId: this.$route.params.repoId,
                    docId: unitId,
                    method: 'remote-branch',
                    branch: pushData.prBranch,
                });
                await this.afterSuccessfulSave({ pushData, unitId, method: 'remote-branch' });
                await this.handleSuccessCreateBranchOrPR({
                    pushData,
                    unitId,
                    goToBranch: pushData.prBranch,
                });
            } else {
                await swal({ title: 'Failed to open remote branch', content: SWAL_CONTACT_US_CONTENT() });
            }
            this.loadingCreatingPR = false;
        },
        async openPR(pushData) {
            // Clear draft timers
            clearTimeout(this.debouncedDraftSaver);

            if (this.loadingCreatingPR || this.loadingPushingToBranch) {
                return;
            }
            this.loadingCreatingPR = true;
            let unitToSave;
            try {
                unitToSave = await this.saveToDbAndPrepareForFileSave();
            } catch (error) {
                this.loadingCreatingPR = false;
                this.$logger.error(`Failed to save doc in DB: ${error}`, { module: 'unit-form' });
                await swal({ title: 'Failed to save doc', content: SWAL_CONTACT_US_CONTENT() });
                return;
            }
            const unitId = unitToSave.id;
            // Generate link to the doc
            const linkToUnit = this.getAppLink(`${this.getRepoPath(this.$route.params.repoId)}/docs/${unitId}`, false);

            const response = await createPR({
                swmFile: unitToSave,
                originalSwmFile: this.originalSwmFromFile,
                repoId: this.$route.params.repoId,
                shouldExportToMD: this.shouldExportSwmToMD,
                commitMessage: pushData.commitMessage,
                branch: pushData.branch,
                prBranch: pushData.prBranch,
                link: linkToUnit,
                swmdFileNameBeforeEdit: this.fs_getSwmdFileNameInRepo(this.$route.params.repoId, unitId),
                isNew: this.isNewUnit,
            });
            if (response.code === SUCCESS_RETURN_CODE) {
                // Important: open the new PR window here, after the save process had already finished.
                // Otherwise we steal focus from the application tab, and the browser will throttle it
                // mercilessly, making the save operation take many seconds, or even minutes.
                if (!window.open(response.url, '_blank')) {
                    this.notifyNewPrPopupBlocker(response.url);
                }
                await addDocContribution({
                    user: this.user,
                    repoId: this.$route.params.repoId,
                    docId: unitId,
                    method: 'pr',
                    branch: pushData.prBranch,
                });
                await this.afterSuccessfulSave({ pushData, unitId, method: 'pr' });
                await this.handleSuccessCreateBranchOrPR({ pushData, unitId, goToBranch: pushData.prBranch });
            } else {
                const changeRequestName = await gitwrapper.getChangeRequestName({ repoId: this.$route.params.repoId });
                await swal({ title: `Failed to open ${changeRequestName}`, content: SWAL_CONTACT_US_CONTENT() });
            }
            this.loadingCreatingPR = false;
        },
        notifyNewPrPopupBlocker(prUrl) {
            this.showToast(
                'We tried to open your request in a new tab, but your browser blocked us.<br/>' +
                'For a better experience, please allow popups for this site.',
                {
                    autoClose: false,
                    action: [
                        {
                            text: 'Close',
                            onClick: (event, toastObject) => {
                                toastObject.goAway(0);
                            },
                        },
                        {
                            text: 'Go to Request',
                            onClick: (event, toastObject) => {
                                window.open(prUrl, '_blank');
                                toastObject.goAway(0);
                            },
                        },
                    ],
                }
            );
        },
        async afterSuccessfulSave({ pushData, unitId, method }) {
            await this.refreshContributors({ repoId: this.$route.params.repoId, unitId });
            await this.clearSwmDrafts();
            this.updatePreventNavigation(false);
            this.logDocumentChangedEvent(unitId);
            this.reportDocSaved({ method, unitId, pushData });
            if (this.generatedDocumentId) {
                this.repoIgnoreGeneratedDocument({
                    repoId: this.$route.params.repoId,
                    generatedDocId: this.generatedDocumentId,
                    savedDocId: unitId,
                });
            }
        },
        async handleSuccessCreateBranchOrPR({ pushData, unitId, goToBranch = undefined }) {
            const branch = goToBranch ? goToBranch : await this.getCurrentOrDefaultBranch(this.$route.params.repoId);
            this.isSavingToNewBranch = true;
            if (this.isNewUnit) {
                this.navigateToRepoPage({ highlightedUnitId: unitId }, branch);

                if (goToBranch) {
                    this.showToast(`Switched to branch "${goToBranch}"`);
                }
            } else {
                if (this.getPreviousRoute.includes('/status')) {
                    this.navigateToPageAndTerminateWorker({
                        newRoute: this.getPreviousRoute,
                        newBranch: pushData.prBranch,
                    });
                } else {
                    this.navigateToUnitPageInContext(unitId, pushData.prBranch);
                }
            }
        },
        async logDocumentChangedEvent(unitId) {
            let eventCode;
            if (this.isDoc) {
                eventCode =
                    (this.isUnitCreatedFromInsights && SWIMM_EVENTS.DOC_CREATED_FROM_SUGGESTION) ||
                    (this.isNewUnit && SWIMM_EVENTS.DOC_CREATED) ||
                    SWIMM_EVENTS.DOC_UPDATED;
            } else {
                eventCode = this.isNewUnit ? SWIMM_EVENTS.EXERCISE_CREATED : SWIMM_EVENTS.EXERCISE_UPDATED;
            }
            await this.logEvent({
                swimmEventCode: eventCode.code,
                repoId: this.$route.params.repoId,
                repoName: this.db_getRepoMetadata(this.$route.params.repoId).name || '',
                srcId: unitId,
                srcName: this.swm.name,
            });
        },
        async navigateToUnitPageInContext(unitId, branch = '') {
            // docs have a '/docs' edit route but '/units' display route.
            const currentPath = this.$route.path;
            // remove 'new' or 'edit'
            const route = this.isNewUnit
                ? currentPath.substr(0, currentPath.lastIndexOf('new')) + unitId
                : currentPath.substr(0, currentPath.lastIndexOf('/edit'));

            await this.navigateToPageAndTerminateWorker({ newRoute: route, newBranch: branch });
        },
        async saveSwimmDocInDatabase() {
            const taskEmpty = this.isTaskEmpty(this.swm);
            let newUnit = {};
            if (!this.isNewUnit) {
                const unitFromDB = this.swimmFromDb;
                newUnit = { ...unitFromDB, id: this.$route.params.unitId };
            } else {
                newUnit = { id: this.generateUnitId() };
            }
            delete newUnit['assignments'];
            delete newUnit['contributors'];
            delete newUnit['thanks'];
            newUnit = {
                ...newUnit,
                name: this.swm.name,
                type: 'unit',
                play_mode: taskEmpty ? UNIT_PLAY_MODES.WALKTHROUGH : UNIT_PLAY_MODES.HANDS_ON,
                file_version: SWM_SCHEMA_VERSION,
                app_version: PJSON_VERSION,
                hunks_count: this.snippetsCount,
            };
            const unitId = await this.saveResourceInFirebaseDocument({
                resourceName: 'swimms',
                resource: newUnit,
                containerDocId: this.$route.params.repoId,
                shouldSaveCreationDetails: this.isNewUnit,
            });
            return unitId;
        },

        isTaskEmpty(swm) {
            return !(swm.task && swm.task.dod && swm.task.dod.length > 0);
        },

        unitHasDiff(swm) {
            // check if the content contains a snippet
            return swm.content.some((cell) => cell.type === SwmCellType.Snippet);
        },
        isSwmContainingSymbolsByStatus({ applicabilityStatusTypes }) {
            if (!this.swm.symbols) {
                return false;
            }
            const symbols = Object.keys(this.swm.symbols).filter((symbol) =>
                applicabilityStatusTypes.includes(this.swm.symbols[symbol].applicability)
            );
            if (symbols.length > 0) {
                const swmString = JSON.stringify(this.swm);
                return symbols.some((symbol) => {
                    const symbolObj = this.swm.symbols[symbol];
                    let symbolRegex = null;
                    switch (symbolObj.type) {
                        case SwmSymbolType.PATH:
                            symbolRegex = getSymbolPathRegex(symbol);
                            break;
                        case SwmSymbolType.GENERIC_TEXT:
                            symbolRegex = getSymbolTextRegex(symbol);
                            break;
                        case SwmSymbolType.LINK:
                            symbolRegex = getSymbolLinkRegex(symbol);
                            break;
                    }
                    return swmString.match(symbolRegex);
                });
            }
            return false;
        },
        getSwmContainingSymbolsByStatus({ applicabilityStatusTypes }) {
            let symbols = Object.keys(this.swm.symbols).filter((symbol) =>
                applicabilityStatusTypes.includes(this.swm.symbols[symbol].applicability)
            );
            if (symbols.length > 0) {
                const swmString = JSON.stringify(this.swm);
                symbols = symbols
                    .filter((symbol) => {
                        const symbolObj = this.swm.symbols[symbol];
                        let symbolRegex = null;
                        switch (symbolObj.type) {
                            case SwmSymbolType.PATH:
                                symbolRegex = getSymbolPathRegex(symbol);
                                break;
                            case SwmSymbolType.GENERIC_TEXT:
                                symbolRegex = getSymbolTextRegex(symbol);
                                break;
                            case SwmSymbolType.LINK:
                                symbolRegex = getSymbolLinkRegex(symbol);
                                break;
                        }
                        return swmString.match(symbolRegex) !== null;
                    })
                    .map((symbol) => {
                        const symbolObj = this.swm.symbols[symbol];

                        return {
                            ...symbolObj,
                            tempId: this.getCellTempIdFromSymbol(symbol, symbolObj.type),
                        };
                    });
            }
            return symbols;
        },
        /**
         * Checks if the content array has a unit with the provided applicability status
         * @param hunkApplicabilityStatusType - one of the ApplicabilityStatus types
         * @return {boolean}
         */
        isPatchContainingHunksByType({ hunkApplicabilityStatusType }) {
            if (!Object.values(ApplicabilityStatus).includes(hunkApplicabilityStatusType)) {
                return false;
            }
            for (const cell of this.snippets) {
                if (cell.applicability && cell.applicability === hunkApplicabilityStatusType) {
                    return true;
                }
            }
            return false;
        },
        async prepareUnitBeforeSave(unitToSave) {
            unitToSave = cleanSwmRuntimeKeys(unitToSave);
            this.cleanContent(unitToSave);
            this.updateSymbols();
            this.updateSwimmLinks(unitToSave);
            unitToSave = cleanSymbolsRuntimeKey(unitToSave);
            if (unitToSave.task) {
                unitToSave.task = {
                    dod: unitToSave.task.dod,
                    tests: unitToSave.task.tests.filter((test) => test !== ''),
                    hints: unitToSave.task.hints.filter((hint) => hint !== ''),
                };
            }
            return unitToSave;
        },
        async clearSwmDrafts() {
            // Discard draft if exists
            if (this.swm.draftId) {
                const branch = await this.getCurrentOrDefaultBranch(this.$route.params.repoId);
                await deleteSWMDraft({ swm: this.swm, repoId: this.$route.params.repoId, branch });
            }
        },
        updateSymbols() {
            // remove symbols that are not used any more
            const symbols = Object.keys(this.swm.symbols);
            if (symbols.length > 0) {
                const swmCommentsString = JSON.stringify(this.swm.content.map((content) => content.comments || content.text));
                symbols.forEach((symbol) => this.updateSymbol(symbol, swmCommentsString));
            }
        },
        updateSymbol(symbol, swmCommentsString) {
            if (!symbol || !this.swm.symbols || !this.swm.symbols[symbol]) {
                return;
            }

            const finalSwmString =
                swmCommentsString || JSON.stringify(this.swm.content.map((content) => content.comments || content.text));
            const symbolObj = this.swm.symbols[symbol];
            let symbolRegex = null;
            switch (symbolObj.type) {
                case SwmSymbolType.PATH:
                    symbolRegex = getSymbolPathRegex(symbol);
                    break;
                case SwmSymbolType.GENERIC_TEXT:
                    symbolRegex = getSymbolTextRegex(symbol);
                    break;
                case SwmSymbolType.LINK:
                    symbolRegex = getSymbolLinkRegex(symbol);
                    break;
                case SwmSymbolType.TEXT_PLACEHOLDER:
                    // JSON.stringify so that text matches the finalSwmString (escaping is added)
                    const stringifiedText = JSON.stringify(symbolObj.text);
                    // slice to remove the quotations ("") the JSON.stringify added
                    const symbolText = stringifiedText.slice(1, -1);
                    symbolRegex = getTextPlaceholderRegex(symbolText, symbol);
                    break;
            }
            if (!finalSwmString.match(symbolRegex)) {
                this.tempDeletedSymbols[symbol] = this.swm.symbols[symbol];
                Vue.delete(this.swm.symbols, symbol);
            }
            this.updateReviewData();
        },
        addPathSymbol(symbolData) {
            if (!this.swm.symbols) {
                return;
            }
            this.swm.symbols[symbolData.symbol] = {
                type: SwmSymbolType.PATH,
                text: symbolData.path,
                path: symbolData.path,
                applicability: ApplicabilityStatus.Verified,
            };
            this.updateReviewData();
        },
        addGenericTextSymbol(symbolData) {
            if (!this.swm.symbols || this.swm.symbols[symbolData.symbol]) {
                return;
            }
            this.swm.symbols[symbolData.symbol] = {
                ...symbolData,
                type: SwmSymbolType.GENERIC_TEXT,
                applicability: ApplicabilityStatus.Verified,
            };
            this.updateReviewData();
        },
        addLinkSymbol(symbolData) {
            if (!this.swm.symbols || this.swm.symbols[symbolData.symbol]) {
                return;
            }
            this.swm.symbols[symbolData.symbol] = {
                type: SwmSymbolType.LINK,
                swimmId: symbolData.swimmId,
                repoId: symbolData.repoId,
                text: symbolData.name,
                applicability: ApplicabilityStatus.Verified,
                swimmType: symbolData.swimmType,
            };
            this.updateReviewData();
        },
        cleanContent(unit) {
            unit.content.forEach((cell) => {
                delete cell.tempId;
                delete cell.originalSwm;
            });
        },
        matchOriginalToAutosyncedSnippetCell() {
            this.swm.content.forEach((cell, cellIndex) => {
                if (cell.type === SwmCellType.Snippet && cell.applicability === ApplicabilityStatus.Autosyncable) {
                    cell.originalSwm = { ...this.originalSwmForAutosync.content[cellIndex] };
                }
            });
        },
        getAutoCompleteTokens() {
            for (const snippet of this.snippets) {
                if (snippet.applicability !== ApplicabilityStatus.Outdated) {
                    this.addTokenFromSnippet(snippet);
                }
            }
        },
        addTokenFromSnippet(snippet) {
            const fileBlob = this.swm.meta.file_blobs[snippet.path];
            let lineNumber = snippet.firstLineNumber;
            for (const line of snippet.lines) {
                if (getLineTypeByMarker(line) === HunkChangeLineType.Added) {
                    continue;
                }
                this.addTokensFromSnippetLine({ line, path: snippet.path, lineNumber, fileBlob });
                lineNumber++;
            }
            this.updateReviewData();
        },
        addTokensFromSnippetLine({ line, path, lineNumber, fileBlob }) {
            const slicedLine = line.slice(1);
            const snippetTokens = this.tokenize(slicedLine);
            for (const token of snippetTokens) {
                const tokenId = `${path}-${lineNumber}-${token.index}`;
                if (!this.tokens[tokenId]) {
                    Vue.set(this.tokens, tokenId, {
                        id: uuidv4(),
                        path: path,
                        lineNumber: lineNumber,
                        text: token.text,
                        wordIndex: {
                            start: token.index,
                            end: token.index,
                        },
                        fileBlob,
                        lineData: slicedLine,
                    });
                }
            }
        },
        async loadDuplicateUnitData() {
            this.$logger.debug(
                `Createing a new doc by duplicating an existing doc, docId: ${this.$route.query.unitToDuplicateId}`,
                { module: 'unit-form' }
            );
            await this.loadExistingUnit(this.$route.query.unitToDuplicateId);
        },
        afterLoadUnitToDuplicate() {
            this.$logger.debug('Finished loading doc to duplicate, changing data to make it a new doc', {
                module: 'unit-form',
            });
            delete this.swm.id;
            this.originalSwmFromFile = null; // this is now a new doc, so technically there's no original file
            this.swm.name += ' (COPY)';
            markInlineImagesAsNew({ swmFile: this.swm });
        },
        async loadExistingUnit(unitId = this.$route.params.unitId) {
            this.$logger.debug(`Loading existing doc / exercise, docId: ${unitId}`, { module: 'unit-form' });
            // Make sure unit is stored in state, but do not autosync yet because maybe there is a draft
            await this.setUnitData({ unitId, shouldAutoSync: false, reload: true });
            const repoId = this.$route.params.repoId;
            const swmFromState = this.fs_getUnitFromLocalRepo(unitId, repoId);
            if (!swmFromState) {
                await swal({ title: 'Failed to open document.', content: SWAL_CONTACT_US_CONTENT() });
                this.$logger.error('Failed to find SWM in state', { service: 'unit-form' }); // extreme case, no point in continuing the execution
                return;
            }
            // The SWM content when it was loaded from the file. This SWM data will be used during save, to determine the
            // delta between the old doc and the new one (see also `originalSwmForAutosync`, which is either the loaded unit
            // or an existing draft)
            this.originalSwmFromFile = swmFromState;
            const branch = await this.getCurrentOrDefaultBranch(repoId);

            const foundDraft = await draftExists({ draftId: unitId, repoId: repoId, branch });
            if (!foundDraft) {
                await this.afterLoadExistingUnit({ swmFromState, repoId });
            } else {
                this.$logger.debug(`Found draft for SWM ${unitId}`, { service: 'unit-form' });
                const draftLoadResult = await this.loadDraft({ draftId: unitId });
                await this.afterLoadDraft({ draftLoadResult });
            }
        },
        async loadDraftOfNewUnit(draftId) {
            this.$logger.debug(`Loading draft of new doc, draftId: ${draftId}`, { module: 'unit-form' });
            const draftLoadResult = await this.loadDraft({ draftId });
            await this.afterLoadDraft({ draftLoadResult });
        },
        async loadDraft({ draftId }) {
            const draftLoadResult = await loadProcessedDraftById({
                draftId,
                repoId: this.$route.params.repoId,
                branch: await this.getCurrentOrDefaultBranch(this.$route.params.repoId),
                type: this.localFileType,
            });
            if (draftLoadResult.code !== config.SUCCESS_RETURN_CODE) {
                await swal({ title: 'Failed to load draft.', content: SWAL_CONTACT_US_CONTENT() });
                this.$logger.error(`Failed to load draft "${draftId}": ${draftLoadResult.errorMessage}`, {
                    service: 'unit-form',
                });
                return;
            }
            return draftLoadResult;
        },
        async afterLoadExistingUnit({ swmFromState, repoId }) {
            this.swm = { ...this.swm, ...swmFromState };
            await injectInlineImages({ swmFile: this.swm, repoId });
            await this.afterLoad();
        },
        async afterLoadDraft({ draftLoadResult }) {
            this.swm = { ...this.swm, ...draftLoadResult.unit };
            this.isDraft = true;
            this.generatedDocumentId = draftLoadResult.unit.generatedDocumentId;
            await this.afterLoad({ hasChanged: true });
        },
        async afterLoad({ hasChanged = false, autosync = true } = {}) {
            // Manually set timers on + mark doc as changed when loading draft
            this.hasChanged = hasChanged ? hasChanged : this.hasChanged;
            this.addSnippetIndex = this.swm.content.length;
            if (this.swm.applicabilityStatus === ApplicabilityStatus.Invalid) {
                return;
            }
            if (autosync) {
                if (this.isDoc) {
                    this.autosyncLoadedUnit();
                } else {
                    // For exercises, synchronously autosync the unit
                    await this.autosyncLoadedUnit();
                }
            }
        },
        async autosyncLoadedUnit() {
            this.isRunningAutosync = true; // EditDoc has a $watch on this.swm that considers this flag
            const autosyncResult = await autosyncUnit({
                originalSwmFile: this.swm,
                repoId: this.$route.params.repoId,
                destCommit: await this.getCurrentOrDefaultBranch(this.$route.params.repoId),
            });
            if (!autosyncResult.autosyncedSwmFile) {
                this.$logger.debug(`Autosyncing ${(this.swm && this.swm.id) || 'new doc'} failed.`, { module: 'unit-form' });
                this.isRunningAutosync = false; // EditDoc has a $watch on this.swm that considers this flag
                return;
            }
            this.$logger.debug('Overriding SWM content with autosync result', { module: 'unit-form' });
            this.originalSwmForAutosync = this.swm;
            this.swm = { ...this.swm, ...autosyncResult.autosyncedSwmFile };
            this.matchOriginalToAutosyncedSnippetCell();
            // Replace symbols and smart paths with the autosynced ones
            if (this.swm.symbols) {
                SymbolBus.$emit(
                    'replace-symbols',
                    filterSwmSymbols({ symbols: this.swm.symbols, type: SwmSymbolType.GENERIC_TEXT })
                );
                SymbolBus.$emit(
                    'replace-smartpaths',
                    filterSwmSymbols({ symbols: this.swm.symbols, type: SwmSymbolType.PATH })
                );
            }
            this.getAutoCompleteTokens();
            this.$nextTick(() => {
                this.isRunningAutosync = false; // EditDoc has a $watch on this.swm that considers this flag
            });
            this.$logger.debug(`Autosyncing ${(this.swm && this.swm.id) || 'new doc'} completed.`, { module: 'unit-form' });

            this.afterAutosyncLoadedUnit();
        },
        afterAutosyncLoadedUnit() {
            this.setTempContentIds();
            reportAutosyncedShownInSwm({
                swm: this.swm,
                repoId: this.$route.params.repoId,
                workspaceId: this.$route.params.workspaceId,
                docMode: 'Edit',
            });
            if (this.isUnitDuplicate) {
                this.afterLoadUnitToDuplicate();
            }
        },
        symbolApplicabilityChanged(id, applicability) {
            if (this.swm.symbols[id]) {
                this.swm.symbols[id].applicability = applicability;
                this.updateReviewData();
            }
        },
        async focusOnCell(cellIndex) {
            await this.$nextTick();
            const ref = this.$refs[`${this.swm.id}-cell-${cellIndex}`];
            if (ref) {
                if (this.swm.content && this.swm.content[cellIndex] && this.swm.content[cellIndex].type === SwmCellType.Table) {
                    ref[0].$refs['header-0'][0].focus();
                } else {
                    ref[0].focus();
                }
            }
        },
        goToNextReviewStep() {
            if (this.indexOfReview >= this.reviewData.length - 1) {
                return;
            }
            this.indexOfReview++;
            let cellIndex = this.swm.content.findIndex((cell) => cell.tempId === this.reviewData[this.indexOfReview].tempId);
            if (cellIndex === this.currentIndex) {
                this.goToNextReviewStep();
                return;
            }
            this.goToCell({ cellIndex, indexToRemove: this.currentIndex });
            this.currentIndex = cellIndex;
        },
        goToPreviousReviewStep() {
            if (this.indexOfReview <= 0) {
                return;
            }

            this.indexOfReview--;
            let cellIndex = this.swm.content.findIndex((cell) => cell.tempId === this.reviewData[this.indexOfReview].tempId);
            if (cellIndex === this.currentIndex) {
                this.goToPreviousReviewStep();
                return;
            }
            this.goToCell({ cellIndex, indexToRemove: this.currentIndex });
            this.currentIndex = cellIndex;
        },
        goToCell({ cellIndex, indexToRemove }) {
            if (indexToRemove !== undefined) {
                if (indexToRemove > -1 && indexToRemove <= this.swm.content.length) {
                    const previousItemRef = `${this.swm.id}-cell-${indexToRemove}`;
                    this.$nextTick(() => {
                        this.$refs[previousItemRef][0].$el.classList.remove('focusOnReviewCell');
                    });
                }
            }
            let itemRef = `${this.swm.id}-cell-${cellIndex}`;
            this.$nextTick(() => {
                if (this.$refs[itemRef]) {
                    if (!Object.keys(this.$refs[itemRef][0]).length) {
                        itemRef = `${this.swm.id}-cell-${cellIndex + 1}`;
                    }
                    this.$refs[itemRef][0].$el.classList.add('focusOnReviewCell');
                    this.$refs[itemRef][0].$el.scrollIntoView();
                }
            });
        },
        focusOnTitle() {
            const itemRef = `${this.swm.id}-title`;
            this.$nextTick(() => {
                if (this.$refs[itemRef]) {
                    this.$refs[itemRef].focus();
                }
            });
        },
        removeDeletedFileTokens(fileName) {
            const fileExists = this.swm.content
                .filter((item) => item.type === 'snippet')
                .some((item) => item.path === fileName);
            if (!fileName || fileExists) {
                return;
            }
            Object.entries(this.tokens).forEach(([tokenKey, tokenValue]) => {
                if (tokenValue.path === fileName) {
                    delete this.tokens[tokenKey];
                }
            });
            this.updateReviewData();
        },
        isSwimmIdInDB(swimmId, swimmType, repoId = this.$route.params.repoId) {
            const getSwimmResult =
                swimmType === 'playlist' ? this.db_getPlaylist(repoId, swimmId) : this.db_getSwimm(repoId, swimmId);
            return getSwimmResult && !objectUtils.isEmpty(getSwimmResult);
        },
        updateSwimmLinks(unitToSave) {
            if (!unitToSave.symbols) {
                return;
            }
            for (const symbol of Object.values(unitToSave.symbols).filter((symbol) => symbol.type === SwmSymbolType.LINK)) {
                const swmFromDB =
                    symbol.swimmType === 'playlist'
                        ? this.db_getPlaylist(symbol.repoId, symbol.swimmId)
                        : this.db_getSwimm(symbol.repoId, symbol.swimmId);
                let latestDBName = swmFromDB ? swmFromDB.name : symbol.text;
                if (symbol.repoId !== this.$route.params.repoId) {
                    // if cross repo link - add repo name to link text
                    latestDBName = `${this.db_getRepoMetadata(symbol.repoId).name}/${latestDBName}`;
                }
                symbol.text = latestDBName;
            }
        },
        isUnitExistsInRepoDB(unitId) {
            const swimm = this.db_getSwimm(this.$route.params.repoId, unitId);
            return swimm && !objectUtils.isEmpty(swimm);
        },
        generateUnitId() {
            let newId = shortUuid();
            while (this.isUnitExistsInRepoDB(newId)) {
                newId = shortUuid();
            }
            return newId;
        },
        async setSwimmToRepoSwimmList(swimmToSet) {
            const type = this.localFileType;
            await this.setSwimmToRepoSwmsList({
                repoId: this.$route.params.repoId,
                swimmId: swimmToSet.id,
                swimmFileName: this.isSWMD ? swmdFileName(swimmToSet) : swimmToSet.id,
                type: type,
            });
        },
        hasNonApplicableCells() {
            // Does content have snippet cells that are not verified
            return this.swm.content.some(
                (cell) =>
                    cell.type === SwmCellType.Snippet && cell.applicability && cell.applicability !== ApplicabilityStatus.Verified
            );
        },
        attemptDraftSave() {
            // Avoid swm changes done by the draft saving process to trigger another draft save
            if (this.savingDraft || this.loadingCreatingPR || this.loadingPushingToBranch || this.saving) {
                return;
            }
            clearTimeout(this.debouncedDraftSaver);
            this.debouncedDraftSaver = setTimeout(this.handleDraftSave, 1500);
        },
        async handleDraftSave() {
            clearTimeout(this.debouncedDraftSaver);
            if (
                this.loadingCreatingPR ||
                this.loadingPushingToBranch ||
                this.savingDraft ||
                this.$route.params.repoId === undefined ||
                this.snippetEditorModal.show // Don't save drafts with opened drawer as it reloads files
            ) {
                return;
            }
            if (this.hasNonApplicableCells()) {
                return;
            }
            this.savingDraft = true;

            // Saving swm file as is;
            const swmToSave = this.swm;
            const repoId = this.$route.params.repoId;
            const branch = await this.getCurrentOrDefaultBranch(repoId);
            const draftId = await saveSwmDraft({
                swm: swmToSave,
                repoId,
                branch,
                type: this.localFileType,
                generatedDocumentId: this.generatedDocumentId,
            });
            this.swm.draftId = draftId;
            // Allow leaving page after change has been done (draft was saved - you can leave)
            this.updatePreventNavigation(false);
            if (!this.$route.query.draft) {
                const allRepoDocs = await this.db_getSwimms(repoId);
                const timeStamp = new Date();
                this.isFirstDoc = !Object.values(allRepoDocs).some(
                    (doc) => doc.creator === this.user.uid || doc.modifier === this.user.uid
                );
                let analyticsData = {
                    'Edit Start': timeStamp.toISOString(),
                    'User First Document': this.isFirstDoc,
                    DraftID: encodeString(draftId),
                    'Number Of Blocks': swmToSave.content.length,
                    Context: 'Repo',
                    'Repo ID': repoId,
                    'Workspace ID': this.$route.params.workspaceId,
                };
                if (this.$route.query.sgdTemplateId) {
                    analyticsData['Template ID'] = this.$route.query.sgdTemplateId;
                    analyticsData.Context = 'Generated Docs';
                }
                this.analytics.track(productEvents.EDIT_DOC_STARTED, analyticsData, { addRouteParams: true });
                await this.$router.replace({ path: this.$route.fullPath, query: { draft: encodeString(draftId) } });
            }
            // Show auto saved label
            this.$emit('draft-saved');
            this.savingDraft = false;
        },
        handleContainerDiscard() {
            this.handleDiscard((discarded) => {
                if (discarded) {
                    this.cancel();
                }
            });
        },
        async handleDiscard(callback) {
            // Don't save more drafts whlie asking user to delete draft
            clearTimeout(this.debouncedDraftSaver);
            this.updatePreventNavigation(false);

            if (!this.swm.draftId) {
                return callback(true);
            }
            const shouldDelete = await swal({
                title: 'Are you sure you want to delete draft?',
                dangerMode: true,
                buttons: {
                    cancel: true,
                    confirm: { text: 'Delete', visible: true },
                },
            });
            if (!shouldDelete) {
                return callback(false);
            }
            const repoId = this.$route.params.repoId;
            const branch = await this.getCurrentOrDefaultBranch(repoId);
            await deleteSWMDraft({ swm: this.swm, repoId, branch });
            return callback(true);
        },
        async loadLinksReposLists() {
            for (const repoId of getSwmLinksRepos(this.swm)) {
                this.getRepoSwmsLists({ repoId, branch: await this.getCurrentOrDefaultBranch(repoId) });
                this.fetchRepository({ repoId });
                this.fetchRepoChildren({ repoId, children: ['swimms', 'playlists'] });
            }
        },
        loadingLinkRepo(repoId) {
            return (
                !this.db_getSwimms(repoId) ||
                !this.db_getPlaylists(repoId) ||
                !this.fs_getRepoLocalFilesLists(repoId) ||
                !this.db_getRepoMetadata(repoId)
            );
        },
        reportDocSaved({ method, unitId, pushData }) {
            const date = new Date();
            if (this.isDoc) {
                const tokenSymbolsCounts = this.symbolsEntriesFilteredByType(SwmSymbolType.GENERIC_TEXT).length;
                const pathSymbolsCount = this.symbolsEntriesFilteredByType(SwmSymbolType.PATH).length;
                const tableCells = this.swm.content.filter((cell) => cell.type === SwmCellType.Table);
                const imageCells = this.swm.content.filter((cell) => cell.type === SwmCellType.Image);
                const productAnalyticsData = {
                    Method: method,
                    'Document ID': unitId || this.swm.id || 'new',
                    'Document Name': this.swm.name,
                    'Click Origin': pushData.origin,
                    'Total Tokens': tokenSymbolsCounts,
                    'Total Snippets': this.snippetsCount,
                    'Total Paths': pathSymbolsCount,
                    'Save Date': date.toISOString(),
                    'Total Tables': tableCells.length,
                    'Total Images': imageCells.length,
                    'From Branch': pushData.branch,
                    'To Branch': method === 'commit' ? pushData.branch : pushData.prBranch,
                    Context: 'Repo',
                };
                if (this.createdFromTemplate) {
                    productAnalyticsData['Template Name'] = this.templateName;
                }
                if (tableCells.length) {
                    productAnalyticsData['Table Dimensions'] = tableCells
                        .map((table) => `${table.headers.length}X${table.table.length ? table.table[0].length + 1 : 1}`)
                        .join(' | ');
                }

                this.updateProductAnalyticsFieldsFromQuery(productAnalyticsData);
                this.analytics.track(productEvents.DOCUMENT_SAVED, productAnalyticsData, { addRouteParams: true });
            }
        },
        updateProductAnalyticsFieldsFromQuery(productAnalyticsData) {
            if (this.$route.query.source === 'github_app') {
                productAnalyticsData.Origin = 'GitHub App';
                if (this.$route.query.feature === 'doc_from_pr') {
                    productAnalyticsData.Feature = 'doc_from_pr';
                    productAnalyticsData.Origin = this.isNewUnit ? 'New Document' : 'GitHub App';
                }
            }
            if (this.$route.query.sgdTemplateId) {
                productAnalyticsData.Context = 'Generated Docs';
            }
            productAnalyticsData['Save Type'] = this.isNewUnit ? 'create' : 'update';
        },
        setTempContentIds() {
            this.swm.content.forEach((cell) => (cell.tempId = uuidv4()));
            this.updateReviewData();
        },
        getCellTempIdFromSymbol(key, type) {
            for (const cell of this.swm.content) {
                const swmString = JSON.stringify(cell);
                let symbolRegex = null;
                switch (type) {
                    case SwmSymbolType.PATH:
                        symbolRegex = new RegExp(`\\[\\[sym:.*?\\(${key}\\)\\]\\]`, 'g');
                        break;
                    case SwmSymbolType.GENERIC_TEXT:
                        symbolRegex = new RegExp(`\\[\\[sym-text:.*?\\(${key}\\)\\]\\]`, 'g');
                        break;
                    case SwmSymbolType.LINK:
                        symbolRegex = new RegExp(`\\[\\[sym-link:\\(${key}\\).*?\\]\\]`, 'g');
                        break;
                }
                if (swmString.match(symbolRegex) !== null) {
                    return cell.tempId;
                }
            }
            return undefined;
        },
        sortSymbolCells(reviewCells) {
            const sortedTempIds = this.swm.content.map((cell) => cell.tempId);
            return reviewCells.sort((a, b) => sortedTempIds.indexOf(a.tempId) - sortedTempIds.indexOf(b.tempId));
        },
        updateReviewData() {
            if (this.isDoc) {
                this.setReviewData();
            }
        },
        symbolsEntriesFilteredByType(type) {
            return this.swm.symbols ? Object.values(this.swm.symbols).filter((symbol) => symbol.type === type) : [];
        },
    },
};

export default unitForm;

import { SWIMMER_STATUSES, UNIT_PLAY_MODES } from 'Shared/config';
import Vue from 'vue';
import firebase from 'firebase/compat/app';
import 'firebase/compat/auth';
import * as exampleDataAdapter from '@/adapters-common/example_data';
import { DEMO_CONTENT_IDS } from '@/common/utils/common-definitions';
import { objectUtils } from 'Shared/objectUtils';
import logger from 'Shared/logger';
import { v4 as uuidv4 } from 'uuid';
import { StatusCodes } from 'http-status-codes';
import * as firestore from '@/adapters-common/firestore-wrapper';
import * as config from 'Shared/config';
import { getRepoIsPrivate, saveWorkspaceToFirestore } from '@/common/utils/database-utils';
import { incrementResourceDBViews } from '@/common/utils/workspace-utils';
import { CloudFunctions } from '@/common/utils/cloud-functions-utils';
import { DEMO_WORKSPACE } from '@/modules/demo/demoData';
import { fetchDocContributors } from '@/modules/doc-contributions/services/doc-contributors-utils';
import { fetchDocAssignments } from '@/modules/doc-assignments/services/doc-assignments-utils';

const emptyRepo = () => ({ metadata: {}, swimms: {}, playlists: {}, swimmers: {}, lifeguards: {}, subscribed: false });
const emptyWorkspace = () => ({
    logo: '',
    name: '',
    repositories: [],
    plans: {},
    workspace_users: {},
    workspace_admins: {},
    invites: [],
    invite_requests: [],
    counter_workspace_users: 0,
    counter_workspace_admins: 0,
});
const emptyUpvotes = () => ({ workspace: {}, repo: {} });
const emptyRepoUpvotes = () => ({ swimm: {}, playlist: {} });
const emptyWorkspaceUpvotes = () => ({ plan: {} });

const getDefaultState = () => ({
    repositories: {},
    workspaces: {},
    invitedWorkspaces: {},
    upvotes: emptyUpvotes(),
    hasFetchedUserWorkspaces: false,
    hasFetchedWorkspacesInvites: false,
    hasFetchedUserUpvotes: false,
    domainSettings: {},
    notifications: [],
});

export default {
    namespaced: true,
    state: getDefaultState(),
    mutations: {
        RESET_STATE(state) {
            Object.assign(state, getDefaultState());
        },
        SET_REPO_METADATA(state, args) {
            if (!(args.repoId in state.repositories)) {
                Vue.set(state.repositories, args.repoId, emptyRepo());
            }
            Vue.set(state.repositories[args.repoId], 'metadata', { ...args.resource, id: args.repoId });
        },
        SET_REPO_RESOURCE(state, args) {
            if (!(args.repoId in state.repositories)) {
                Vue.set(state.repositories, args.repoId, emptyRepo());
            }
            // For backward compability
            if (args.resourceName === 'swimms' && !('type' in args.resource)) {
                args.resource.type = 'unit';
            }
            if ('id' in args.resource) {
                Vue.set(state.repositories[args.repoId][args.resourceName], args.resource.id, args.resource);
            } else {
                Vue.set(state.repositories[args.repoId], args.resourceName, args.resource);
            }
        },
        SET_REPO_SWIMMER(state, args) {
            if (!(args.repoId in state.repositories)) {
                Vue.set(state.repositories, args.repoId, emptyRepo());
            }
            Vue.set(state.repositories[args.repoId]['swimmers'], args.uid, args.data);
        },
        SET_REPO_LIFEGUARD(state, args) {
            if (!(args.repoId in state.repositories)) {
                Vue.set(state.repositories, args.repoId, emptyRepo());
            }
            Vue.set(state.repositories[args.repoId]['lifeguards'], args.uid, args.data);
        },
        SET_REPO_SWIMMER_STATUS(state, args) {
            if (!('swimmers' in state.repositories[args.repoId])) {
                Vue.set(state.repositories[args.repoId], 'swimmers', {});
            }
            if (!(args.userId in state.repositories[args.repoId].swimmers)) {
                Vue.set(state.repositories[args.repoId].swimmers, args.userId, {});
            }
            if (!state.repositories[args.repoId].swimmers[args.userId].swimms_status) {
                Vue.set(state.repositories[args.repoId].swimmers[args.userId], 'swimms_status', {});
            }
            if (!state.repositories[args.repoId].swimmers[args.userId].playlists_status) {
                Vue.set(state.repositories[args.repoId].swimmers[args.userId], 'playlists_status', {});
            }
            if (args.id) {
                Vue.set(state.repositories[args.repoId].swimmers[args.userId].swimms_status, args.id, args.status);
            }
            if (args.swimmerName && !state.repositories[args.repoId].swimmers[args.userId].name) {
                Vue.set(state.repositories[args.repoId].swimmers[args.userId], 'name', args.swimmerName);
            }
        },
        SET_REPO_SUBSCRIBED(state, args) {
            if (!(args.repoId in state.repositories)) {
                Vue.set(state.repositories, args.repoId, emptyRepo());
            }
            Vue.set(state.repositories[args.repoId], 'subscribed', true);
        },
        REMOVE_STORE_RESOURCE(state, args) {
            Vue.delete(state[args.storeType][args.containerDocId][args.resourceName], args.resourceId);
        },
        SET_HAS_FETCHED_WORKSPACES_INVITES(state, args) {
            Vue.set(state, 'hasFetchedWorkspacesInvites', args.value);
        },
        SET_WORKSPACE(state, args) {
            Vue.set(state.workspaces, args.workspaceId, { ...emptyWorkspace(), ...args.workspace });
        },
        SET_REPOSITORY(state, args) {
            state.workspaces[args.workspaceId].repositories.push(args.repoId);
        },
        UPDATE_WORKSPACE(state, args) {
            Vue.set(state.workspaces, args.workspaceId, { ...state.workspaces[args.workspaceId], ...args.workspace });
        },
        SET_INVITED_WORKSPACE(state, args) {
            Vue.set(state.invitedWorkspaces, args.workspaceId, { ...args.workspace });
        },
        REMOVE_INVITED_WORKSPACE(state, args) {
            Vue.delete(state.invitedWorkspaces, args.workspaceId);
        },
        INCREMENT_RESOURCE_VIEWS(state, args) {
            const { repoId, resourceId, type } = args;
            const views = state.repositories[repoId][type][resourceId].views;
            if (views) {
                Vue.set(state.repositories[repoId][type][resourceId], 'views', views + 1);
            } else {
                Vue.set(state.repositories[repoId][type][resourceId], 'views', 1);
            }
        },
        REMOVE_WORKSPACE_INVITE(state, args) {
            const index = state.workspaces[args.workspaceId].invites.findIndex((invite) => invite === args.email);
            if (index > -1) {
                state.workspaces[args.workspaceId].invites.splice(index, 1);
            }
        },
        REMOVE_WORKSPACE_INVITE_REQUEST(state, args) {
            const index = state.workspaces[args.workspaceId]['invite_requests'].findIndex((invite) => invite === args.email);
            if (index > -1) {
                state.workspaces[args.workspaceId]['invite_requests'].splice(index, 1);
            }
        },
        ADD_WORKSPACE_INVITE(state, args) {
            state.workspaces[args.workspaceId].invites.push(args.email);
        },
        REMOVE_WORKSPACE(state, args) {
            Vue.delete(state.workspaces, args.workspaceId);
        },
        SET_DOC_ASSIGNMENTS(state, args) {
            const { repoId, unitId, resourceName, resource } = args;
            if (!(repoId in state.repositories)) {
                return;
            }

            Vue.set(state.repositories[repoId].swimms[unitId], 'assignments', resource);
        },
        SET_DOC_CONTRIBUTOR(state, args) {
            const { repoId, unitId, resource } = args;
            if (
                !state.repositories ||
                !(repoId in state.repositories) ||
                !state.repositories[repoId].swimms ||
                !(unitId in state.repositories[repoId].swimms)
            ) {
                return;
            }
            if (!state.repositories[repoId].swimms[unitId].contributors) {
                Vue.set(state.repositories[repoId].swimms[unitId], 'contributors', {});
            }
            Vue.set(state.repositories[repoId].swimms[unitId].contributors, resource.id, resource);
        },
        SET_DOC_THANK(state, args) {
            // note: this is not the sub collection but the unification of
            // contributor with the creator
            const { repoId, unitId, resource } = args;
            if (
                !state.repositories ||
                !(repoId in state.repositories) ||
                !state.repositories[repoId].swimms ||
                !(unitId in state.repositories[repoId].swimms)
            ) {
                return;
            }
            if (!state.repositories[repoId].swimms[unitId].thanks) {
                Vue.set(state.repositories[repoId].swimms[unitId], 'thanks', {});
            }
            Vue.set(state.repositories[repoId].swimms[unitId].thanks, resource.id, resource);
        },
        SET_WORKSPACE_RESOURCE(state, args) {
            const { workspaceId, resourceName, resource } = args;
            if (!(workspaceId in state.workspaces)) {
                Vue.set(state.workspaces, workspaceId, emptyWorkspace());
            }
            if ('id' in args.resource) {
                Vue.set(state.workspaces[workspaceId][resourceName], resource.id, resource);
            } else {
                Vue.set(state.workspaces[workspaceId], resourceName, resource);
            }
        },
        SET_WORKSPACE_ADMIN(state, args) {
            const { workspaceId, resourceName, resource } = args;
            Vue.set(state.workspaces[workspaceId][resourceName], resource.uid, resource);
        },
        REFRESH_WORKSPACE_LICENSE(state, args) {
            const { workspaceId, license } = args;
            state.workspaces[workspaceId].license = license;
        },
        SET_UPVOTE(state, args) {
            const { containerType, containerId, resourceType, resourceId, value, originalValue } = args;
            if (!(containerId in state.upvotes[containerType])) {
                Vue.set(
                    state.upvotes[containerType],
                    containerId,
                    containerType === 'repo' ? emptyRepoUpvotes() : emptyWorkspaceUpvotes()
                );
            }
            if (!(resourceId in state.upvotes[containerType][containerId][resourceType])) {
                Vue.set(state.upvotes[containerType][containerId][resourceType], resourceId, { originalValue: originalValue });
            }
            Vue.set(state.upvotes[containerType][containerId][resourceType][resourceId], 'upvote', value);
        },
        SET_HAS_FETCHED_USER_UPVOTES(state, args) {
            Vue.set(state, 'hasFetchedUserUpvotes', args.value);
        },
        SET_DOMAIN_SETTINGS(state, args) {
            Vue.set(state, 'domainSettings', args);
        },
        SET_USER_NOTIFICATIONS(state, args) {
            const { notifications } = args;

            Vue.set(state, 'notifications', notifications);
        },
    },
    actions: {
        resetState({ commit }) {
            commit('RESET_STATE');
        },
        removeWorkspace({ commit }, workspaceId) {
            commit('REMOVE_WORKSPACE', { workspaceId: workspaceId });
        },
        incrementResourceViews({ commit }, args) {
            const type = args.type === 'swimms' ? 'swimm' : 'playlists';
            const resourcePath = `repo-${args.repoId}-${type}-${args.resourceId}`;
            incrementResourceDBViews(resourcePath);
            commit('INCREMENT_RESOURCE_VIEWS', args);
        },
        async fetchSwimmerWorkspaces({ commit, dispatch, state, rootState }) {
            if (state.hasFetchedUserWorkspaces) {
                return;
            }

            const { user } = rootState.auth;
            const response = await firestore.getCollectionGroupRefWithWhereClause(
                firestore.collectionNames.WORKSPACES_USERS,
                ['uid', '==', user.uid]
            );
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Got error while getting user workspaces: ${response.errorMessage}`, { module: 'database' });
                return;
            }

            const workspacesQuerySnapshot = response.data;
            const workspacesIds = [...new Set(workspacesQuerySnapshot.docs.map((doc) => doc.ref.parent.parent.id))];
            const fetchWorkspacesResults = await Promise.allSettled(
                workspacesIds.map(async (workspaceId) => {
                    await dispatch('fetchWorkspace', { workspaceId: workspaceId });
                    commit('SET_WORKSPACE_RESOURCE', {
                        resourceName: firestore.collectionNames.WORKSPACES_USERS,
                        workspaceId,
                        resource: { id: user.uid, ...user },
                    }); // so that we know user is in a workspace
                    await dispatch('fetchWorkspaceAdmin', { workspaceId: workspaceId });
                })
            );

            fetchWorkspacesResults.forEach((result) => {
                if (result.status === 'rejected') {
                    logger.error(`Failed to fetch a swimmer workspace. Details: ${result.reason}`, {
                        service: 'database',
                    });
                }
            });
        },
        async fetchAllWorkspaceRepos({ dispatch, state, getters }, workspaceId) {
            // Fetch all the repositories of a workspace (if not already in the state)
            await Promise.all(
                getters.db_getWorkspaceRepoIds(workspaceId).map(async (repoId) => {
                    if (!(repoId in state.repositories)) {
                        await dispatch('fetchRepository', { repoId: repoId });
                    }
                })
            );
        },
        async fetchAllWorkspaceReposChildren({ dispatch, getters, rootState }, args) {
            const { user } = rootState.auth;
            const repoIds = [...new Set(getters.db_getWorkspaceRepoIds(args.workspaceId))];

            // A mapping function that gets a repo id and fetch the repo's child resources and the swimmer status
            const fetchRepoContentMap = async (repoId) => {
                await Promise.all([
                    await dispatch('fetchRepoChildren', { repoId, children: ['swimms', 'playlists'] }),
                    await dispatch('fetchSwimmerStatus', { repoId, userId: user.uid }),
                ]);
            };

            // For every repo, fetch the swimmer data (current user) and run the above mapping function to get the repo resources
            await Promise.all(
                repoIds.map(async (repoId) => {
                    await dispatch('fetchRepoSwimmer', { repoId, userId: user.uid });
                    if (getters.db_isRepoSwimmer(repoId, user.uid)) {
                        await fetchRepoContentMap(repoId);
                    }
                })
            );
        },
        setCustomWorkspace({ commit, rootState }, { workspace }) {
            const { user } = rootState.auth;

            commit('SET_WORKSPACE', {
                workspaceId: workspace.id,
                workspace: { ...workspace },
            });

            commit('SET_WORKSPACE_RESOURCE', {
                resourceName: firestore.collectionNames.WORKSPACES_USERS,
                workspaceId: workspace.id,
                resource: { id: user.uid, ...user },
            }); // so that we know user is in a workspace
        },
        async fetchWorkspace({ commit, state, dispatch }, args) {
            if (args.workspaceId === DEMO_WORKSPACE.id) {
                dispatch('setCustomWorkspace', { workspace: DEMO_WORKSPACE });
                return;
            }
            if (state.workspaces[args.workspaceId]) {
                return;
            }
            const response = await firestore.getDocFromCollection(firestore.collectionNames.WORKSPACES, args.workspaceId);
            if (response.code === config.SUCCESS_RETURN_CODE) {
                commit('SET_WORKSPACE', {
                    workspaceId: args.workspaceId,
                    workspace: { ...response.data, id: args.workspaceId },
                });
            } else {
                logger.error(`Error getting workspace data: ${response.errorMessage}`, { module: 'database' });
                throw response.errorMessage;
            }
        },
        async fetchWorkspaceInvites({ commit, state, rootState }) {
            if (state.hasFetchedWorkspacesInvites) {
                return Object.values(state.invitedWorkspaces);
            }

            const { user } = rootState.auth;
            const response = await firestore.getDocsRefWithWhereClause(firestore.collectionNames.WORKSPACES, [
                'invites',
                'array-contains',
                user.email,
            ]);

            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching workspaces invites: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            const workspacesQuerySnapshot = response.data;
            for (const doc of workspacesQuerySnapshot.docs) {
                if (!state.invitedWorkspaces[doc.id]) {
                    commit('SET_INVITED_WORKSPACE', { workspaceId: doc.id, workspace: { ...doc.data(), id: doc.id } });
                }
            }
            commit('SET_HAS_FETCHED_WORKSPACES_INVITES', { value: true });
            return Object.values(state.invitedWorkspaces);
        },
        async fetchWorkspaceAdmin({ commit, state, rootState }, args) {
            const { user } = rootState.auth;
            const { workspaceId } = args;
            if (
                state.workspaces[workspaceId] &&
                (!state.workspaces[workspaceId]['workspace_admins'] ||
                    !state.workspaces[workspaceId]['workspace_admins'][user.uid])
            ) {
                const response = await firestore.getDocRefFromSubCollection(
                    firestore.collectionNames.WORKSPACES,
                    workspaceId,
                    firestore.collectionNames.WORKSPACES_ADMINS,
                    user.uid
                );

                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Error fetching workspaces admin: ${response.errorMessage}`, { module: 'database' });
                    return;
                }

                if (response.data.exists) {
                    commit('SET_WORKSPACE_ADMIN', {
                        workspaceId,
                        resourceName: 'workspace_admins',
                        resource: response.data.data(),
                    });
                }
            }
        },
        /**
         * Gets a specific document id and child collection names and fetches the list of child collections from firebase
         * @param args.documentId - the firebase document id to fetch from
         * @param args.children - array of child collections names to fetch
         * @param args.containerCollection - name of the collection containing the document to fetch from
         * @return {Promise<void>}
         */
        async fetchDocumentChildCollections({ commit }, args) {
            const { documentId, containerCollection, children = [] } = args;
            if (documentId === DEMO_WORKSPACE.id) {
                return;
            }

            if (children.length < 1) {
                return;
            }

            await Promise.all(
                children.map(async (child) => {
                    const response = await firestore.getSubCollection(containerCollection, documentId, child);
                    if (response.code !== config.SUCCESS_RETURN_CODE) {
                        logger.error(`Got error while getting collection ${child}: ${response.errorMessage}`, {
                            service: 'database',
                        });
                    } else {
                        response.data.forEach((doc) => {
                            if (containerCollection === firestore.collectionNames.WORKSPACES) {
                                return commit('SET_WORKSPACE_RESOURCE', {
                                    resourceName: child,
                                    workspaceId: documentId,
                                    resource: { ...doc.data(), id: doc.id },
                                });
                            }
                        });
                    }
                })
            );
        },
        async fetchUserUpvotes({ commit, state }, args) {
            if (state.hasFetchedUserUpvotes) {
                return;
            }

            const response = await firestore.getSubCollection(
                firestore.collectionNames.UPVOTES,
                args.userId,
                firestore.collectionNames.USER_UPVOTES
            );
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Got error while getting user upvotes: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            response.data.forEach((upvoteDoc) => {
                // upvote Id format: ContainerType-ContainerId-ResourceType-ResourceId, e.g repo-1234-playlist-5678, workspace-1234-plan-5678
                const splittedUpvote = upvoteDoc.id.split('-');
                commit('SET_UPVOTE', {
                    containerType: splittedUpvote[0],
                    containerId: splittedUpvote[1],
                    resourceType: splittedUpvote[2],
                    resourceId: splittedUpvote[3],
                    value: true,
                    originalValue: true,
                });
            });
            commit('SET_HAS_FETCHED_USER_UPVOTES', { value: true });
        },
        async setUpvote({ commit }, args) {
            const { userId, containerType, containerId, resourceType, resourceId, value, originalValue } = args;
            const id = `${containerType}-${containerId}-${resourceType}-${resourceId}`;
            if (value) {
                const response = await firestore.setValuesInDocInSubCollection(
                    firestore.collectionNames.UPVOTES,
                    userId,
                    firestore.collectionNames.USER_UPVOTES,
                    id,
                    { id, containerType, containerId, resourceType, resourceId }
                );
                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error while setting upvote for user ${userId}: ${response.errorMessage}`, {
                        service: 'database',
                    });
                }
            } else {
                const response = await firestore.deleteDocFromSubCollection(
                    firestore.collectionNames.UPVOTES,
                    userId,
                    firestore.collectionNames.USER_UPVOTES,
                    id
                );
                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error while deleting upvote from user ${userId}: ${response.errorMessage}`, {
                        service: 'database',
                    });
                }
            }
            commit('SET_UPVOTE', {
                containerType,
                containerId,
                resourceType,
                resourceId,
                value,
                originalValue: !!originalValue,
            });
        },
        async fetchRepository({ commit, state }, args) {
            const { repoId } = args;
            if (!(repoId in state.repositories && !objectUtils.isEmpty(state.repositories[repoId]))) {
                const response = await firestore.getDocFromCollection(firestore.collectionNames.REPOSITORIES, repoId);
                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error while getting repo: ${response.errorMessage}`, { module: 'database' });
                    return;
                }
                const repoData = response.data;
                const is_private = await getRepoIsPrivate({ repoId, repoData });
                commit('SET_REPO_METADATA', {
                    repoId,
                    resource: { ...repoData, ...(is_private !== undefined ? { is_private } : {}) },
                });
            }
        },
        subscribeToRepository({ commit, dispatch, state }, args) {
            const { repoId, updateChildren = [] } = args;
            if (!state.repositories[repoId] || !state.repositories[repoId].subscribed) {
                return new Promise((resolve, reject) => {
                    const unsubscribe = firebase
                        .firestore()
                        .collection('repositories')
                        .doc(repoId)
                        .onSnapshot(
                            function (repoDocRef) {
                                // TODO - unused var - should be removed?
                                // const oldRepo = { ...state.repositories[repoDocRef.id] }; // spread object so it does not get updated when committing newRepo
                                const newRepo = repoDocRef.data();
                                commit('SET_REPO_METADATA', { repoId: repoDocRef.id, resource: newRepo });
                                commit('SET_REPO_SUBSCRIBED', { repoId: repoDocRef.id });
                                dispatch('fetchRepoChildren', { repoId, children: updateChildren }).then(() => resolve(unsubscribe));
                            },
                            function (error) {
                                logger.error(`Error getting documents: ${error}`, { service: 'database' });
                                reject();
                            }
                        );
                });
            }
        },
        async fetchRepoChildren({ commit, state }, args) {
            const { repoId, children = [] } = args;
            await Promise.all(
                children.map(async (child) => {
                    const response = await firestore.getSubCollection(firestore.collectionNames.REPOSITORIES, repoId, child);
                    if (response.code !== config.SUCCESS_RETURN_CODE) {
                        logger.error(`Got error while getting collection ${child}: ${response.errorMessage}`, {
                            service: 'database',
                        });
                    } else {
                        const childSnapshot = response.data;
                        childSnapshot.forEach((doc) => {
                            if (!!state.repositories[repoId][child][doc.id]) {
                                return;
                            }
                            commit('SET_REPO_RESOURCE', {
                                resourceName: child,
                                repoId,
                                resource: { ...doc.data(), id: doc.id },
                            });
                        });
                    }
                })
            );
        },
        async setDbExampleContentData({ commit, getters }, args) {
            const { repoId } = args;
            if (!repoId) {
                return;
            }
            const repoName = getters.db_getRepoMetadata(repoId).name;
            if (!getters.db_isPlaylistInRepo(repoId, DEMO_CONTENT_IDS.EXAMPLE_PLAYLIST_ID)) {
                const examplePlaylist = exampleDataAdapter.getExamplePlaylistDbData(repoName);
                commit('SET_REPO_RESOURCE', { resourceName: 'playlists', repoId, resource: examplePlaylist });
            }
            if (!getters.db_isUnitInRepo(repoId, DEMO_CONTENT_IDS.EXAMPLE_EXTERNAL_LINK_ID)) {
                const exampleLink = exampleDataAdapter.getExampleExternalLinkDbData();
                commit('SET_REPO_RESOURCE', { resourceName: 'swimms', repoId, resource: exampleLink });
            }
            if (!getters.db_isUnitInRepo(repoId, DEMO_CONTENT_IDS.EXAMPLE_DOC_ID)) {
                const exampleDoc = exampleDataAdapter.getExampleDocDbData(repoName);
                commit('SET_REPO_RESOURCE', { resourceName: 'swimms', repoId, resource: exampleDoc });
            }
        },
        async fetchSwimmerStatus({ commit }, args) {
            const { repoId, userId } = args;
            const response = await firestore.getSubCollectionRecursive(
                [
                    firestore.collectionNames.REPOSITORIES,
                    firestore.collectionNames.SWIMMERS,
                    firestore.collectionNames.SWIMMS_STATUS,
                ],
                [repoId, userId]
            );
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching swimmer status: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            const orderedUnits = response.data;
            if (orderedUnits.empty) {
                commit('SET_REPO_SWIMMER_STATUS', { repoId, userId: userId });
            } else {
                orderedUnits.forEach((doc) => {
                    commit('SET_REPO_SWIMMER_STATUS', { repoId, userId, id: doc.id, status: doc.data() });
                });
            }
        },
        async fetchRepoSwimmer({ commit, state }, args) {
            const { repoId, userId } = args;
            const response = await firestore.getDocFromSubCollection(
                firestore.collectionNames.REPOSITORIES,
                repoId,
                firestore.collectionNames.SWIMMERS,
                userId
            );
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching swimmer: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            const swimmerSnapshot = response.data;
            if (swimmerSnapshot) {
                // if some swimmer data has already been loaded before, e.g. swimms_status / playlists_status
                const existingSwimmer = state.repositories[repoId] && state.repositories[repoId].swimmers[userId];
                commit('SET_REPO_SWIMMER', { uid: userId, repoId, data: { ...swimmerSnapshot, ...existingSwimmer } });
            }
        },
        async isRepoExistOnDB(_, args) {
            const { repoId } = args;
            const response = await firestore.getDocFromCollection(firestore.collectionNames.REPOSITORIES, repoId);
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.debug(`Could not fetch repo with repoId: ${repoId}. Details: ${response.errorMessage}`, {
                    module: 'database',
                });
                return;
            }

            return !!response.data;
        },
        async fetchRepoLifeguard({ commit, state }, args) {
            const { repoId, userId } = args;
            if (
                state.repositories[repoId] &&
                (!state.repositories[repoId]['lifeguards'] || !state.repositories[repoId]['lifeguards'][userId])
            ) {
                const response = await firestore.getDocFromSubCollection(
                    firestore.collectionNames.REPOSITORIES,
                    repoId,
                    firestore.collectionNames.LIFEGUARDS,
                    userId
                );

                if (response.code === config.SUCCESS_RETURN_CODE) {
                    commit('SET_REPO_LIFEGUARD', { uid: userId, repoId, data: response.data });
                }
            }
        },
        /**
         * Creates or updates a provided resource in a specific collection under a specific document in firestore.
         * All params are provided inside args
         * NOTICE! : using serverTimestamp inside the set/add call (to override the values before) is mandatory! otherwise they won't be parsed as timestamp when inserted to firestore.
         * @param args.containerDocId - The containing document id (i.e - the repoId)
         * @param args.containerCollectionType - the type of the collection containing the document to save under ( i.e - workspaces)
         * @param args.resourceName - the name of the collection to save (playlists, swimms, etc.)
         * @param args.resource - the JSON object of the resource to save (i.e - a playlist data object)
         * @param args.updateState - determines if it's an update or creation
         * @param args.shouldSaveCreationDetails - use for saving a new documents with a resource id (i.e users in workspace)
         * @return {Promise<*>}
         */
        async saveResourceInFirebaseDocument({ commit, rootState }, args) {
            const {
                containerDocId,
                resourceName,
                resource,
                updateState = true,
                containerCollectionType = 'repositories',
                shouldSaveCreationDetails = false,
            } = args;
            const { user } = rootState.auth;
            const creation = {
                created: await firestore.firestoreTimestamp(),
                creator: user.uid,
                creator_name: user.nickname,
            };
            const update = {
                modified: await firestore.firestoreTimestamp(),
                modifier: user.uid,
                modifier_name: user.nickname,
            };
            const savedResource = { ...resource, ...creation, ...update };
            const getResponse = firestore.getSubCollectionRef(containerCollectionType, containerDocId, resourceName);
            if (getResponse.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Got error getting resource: ${getResponse.errorMessage}`, { module: 'database' });
                throw getResponse.errorMessage;
            }
            const collectionRef = getResponse.data;
            let savedDocId;
            if ('id' in resource) {
                // we use mergeFields to not update creation values if they already exist in the DB
                const mergeFields = [];
                const keysToIgnore = ['counter_upvotes', 'views'];
                if (shouldSaveCreationDetails) {
                    // In some cases we are saving a new document with a pre-set id and want to keep the creation details on set
                    // e.g swimmers in repo / users in workspace - both have the document id set to the user id
                    // the argument shouldSaveCreationDetails should be set to true only in the creation call of the document
                    mergeFields.push(...Object.keys(savedResource).filter((key) => !keysToIgnore.includes(key)));
                } else {
                    // merge fields should not include creation fields
                    mergeFields.push(
                        ...Object.keys(savedResource).filter((key) => !(key in creation) && !keysToIgnore.includes(key))
                    );
                }
                const fieldsToSet = { ...savedResource, modified: await firestore.firestoreTimestamp() };
                const options = { mergeFields: mergeFields };
                const setResponse = await firestore.setValuesInDocInSubCollection(
                    containerCollectionType,
                    containerDocId,
                    resourceName,
                    resource.id,
                    fieldsToSet,
                    options
                );
                if (setResponse.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error updating resource: ${setResponse.errorMessage}`, { module: 'database' });
                    throw setResponse.errorMessage;
                }
                savedDocId = resource.id; // Use the resource ID because `.set` doesn't send back the document ID
            } else {
                const docToAdd = {
                    ...savedResource,
                    created: await firestore.firestoreTimestamp(),
                    modified: await firestore.firestoreTimestamp(),
                };
                const addResponse = await firestore.addDocToSubCollection(
                    containerCollectionType,
                    containerDocId,
                    resourceName,
                    docToAdd
                );
                if (addResponse.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error adding resource: ${addResponse.errorMessage}`, { module: 'database' });
                    throw addResponse.errorMessage;
                }
                savedDocId = addResponse.data.id;
            }
            if (updateState && savedDocId) {
                // fetch the saved doc so we get the date(created, modified) fields in a json friendly format.
                const getDocResponse = await firestore.getDocFromRef(collectionRef, savedDocId);
                if (getDocResponse.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error getting resource: ${getDocResponse.errorMessage}`, { module: 'database' });
                    throw getDocResponse.errorMessage;
                }
                const savedDocData = getDocResponse.data;
                const commitMethods = {
                    repositories: () =>
                        commit('SET_REPO_RESOURCE', {
                            resourceName,
                            repoId: containerDocId,
                            resource: { ...savedDocData, id: savedDocId },
                        }),
                    workspaces: () =>
                        commit('SET_WORKSPACE_RESOURCE', {
                            resourceName,
                            workspaceId: containerDocId,
                            resource: { ...savedDocData, id: savedDocId },
                        }),
                };
                commitMethods[containerCollectionType]();
            }
            return savedDocId;
        },
        async saveRepository({ commit }, args) {
            if (!args.repoId) {
                logger.error(`Error adding repository, missing repository id`, { module: 'database' });
                return;
            }
            const response = await firestore.setValuesInDoc(firestore.collectionNames.REPOSITORIES, args.repoId, {
                ...args.resource,
                created: await firestore.firestoreTimestamp(),
            });
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error adding document: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            commit('SET_REPO_METADATA', { repoId: args.repoId, resource: args.resource });
        },
        /**
         * Removes a resource in a specific collection under a specific document in firestore.
         * @param args.containerDocId - The containing document id (i.e - the repoId)
         * @param args.containerCollectionType - the type of the collection containing the document to delete ( i.e - repositories)
         * @param args.resourceName - the name of the collection to delete (playlists, swimms, etc.)
         * @param args.resourceId - the id of the resource (firebase document id) to delete (i.e - a playlist id)
         * @return {Promise<*>}
         */
        async removeResourceInFirebaseDocument({ commit }, args) {
            const { containerDocId, resourceName, resourceId, containerCollectionType } = args;
            const response = await firestore.deleteDocFromSubCollection(
                containerCollectionType,
                containerDocId,
                resourceName,
                resourceId
            );
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error deleting resource: ${response.errorMessage}`, { module: 'database' });
                return;
            }

            commit('REMOVE_STORE_RESOURCE', {
                resourceName,
                containerDocId,
                resourceId,
                storeType: containerCollectionType,
            });
        },
        /**
         * Archives a resource (document) in a specific collection in firestore.
         * in example, gets a playlist and copies it under archived_playlists before deleting it from firestore
         * @param args.containerDocId - The containing document id (i.e - the repoId)
         * @param args.containerCollectionType - the type of the collection containing the document to archive ( i.e - repositories)
         * @param args.resourceName - the name of the collection to archive (playlists, swimms, etc.)
         * @param args.resourceId - the id of the resource (firebase document id) to archive (i.e - a playlist id)
         * @return {Promise<*>}
         */
        async archiveResource({ dispatch }, args) {
            const {
                containerDocId,
                resourceName,
                resourceId,
                containerCollectionType = firestore.collectionNames.REPOSITORIES,
            } = args;
            const response = await firestore.getDocFromSubCollection(
                containerCollectionType,
                containerDocId,
                resourceName,
                resourceId
            );

            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching resource: ${response.errorMessage}`, { module: 'database' });
                return;
            }

            const resource = response.data;
            const savingResult = await dispatch('saveResourceInFirebaseDocument', {
                resourceName: `archived_${resourceName}`,
                resource: { ...resource, id: resourceId },
                containerDocId,
                containerCollectionType,
                updateState: false,
            });
            //TODO: handle error better
            if (savingResult.error) {
                logger.error(savingResult.error, { module: 'database' });
            } else {
                await dispatch('removeResourceInFirebaseDocument', {
                    resourceName,
                    resourceId,
                    containerDocId,
                    containerCollectionType,
                });
            }
        },
        async updateSwimmerStatus({ commit }, args) {
            const { status, repoId, userId, resourceId } = args;
            if (!Object.values(SWIMMER_STATUSES).includes(status)) {
                logger.error(`${status} is an invalid swimmer status.`, { module: 'database' });
                return;
            }
            const newStatus = { status: status };
            newStatus[`${status}_date`] = await firestore.firestoreTimestamp();
            const response = await firestore.setValuesInDocSubCollectionRecursive(
                [
                    firestore.collectionNames.REPOSITORIES,
                    firestore.collectionNames.SWIMMERS,
                    firestore.collectionNames.SWIMMS_STATUS,
                ],
                [repoId, userId, resourceId],
                newStatus,
                { merge: true }
            );
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error updating swimmer status: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            // override the firestore serverTimestamp value because it fails on json.stringify(this issue started when we moved to electron)
            newStatus[`${status}_date`] = new Date();
            commit('SET_REPO_SWIMMER_STATUS', { repoId, userId, id: resourceId, status: newStatus });
        },
        async unsubscribeUserFromRepo({ dispatch, rootState }, args) {
            const user = args.user ? args.user : rootState.auth.user;
            const roleListToUnsubscribe = args.roleToRemove === 'swimmer' ? 'swimmers' : 'lifeguards';
            await dispatch('removeResourceInFirebaseDocument', {
                resourceName: roleListToUnsubscribe,
                resourceId: user.uid,
                containerDocId: args.repoId,
                containerCollectionType: 'repositories',
            });
        },
        async saveWorkspace({ commit, rootState }, args) {
            const { user } = rootState.auth;

            const response = await saveWorkspaceToFirestore(args.resource, user);
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                throw response.errorMessage;
            }

            if (response.user) {
                commit('SET_WORKSPACE_RESOURCE', {
                    resourceName: firestore.collectionNames.WORKSPACES_USERS,
                    workspaceId: response.workspaceId,
                    resource: { ...response.user, id: user.uid },
                });
                commit('SET_WORKSPACE_RESOURCE', {
                    resourceName: firestore.collectionNames.WORKSPACES_ADMINS,
                    workspaceId: response.workspaceId,
                    resource: { ...response.user, id: user.uid },
                });
            }

            if (response.workspace) {
                const savedWorkspace = response.workspace;
                const counters = {
                    counter_workspace_users: savedWorkspace.counter_workspace_users || 1,
                    counter_workspace_admins: savedWorkspace.counter_workspace_admins || 1,
                };
                commit(response.wasUpdated ? 'UPDATE_WORKSPACE' : 'SET_WORKSPACE', {
                    workspaceId: response.workspaceId,
                    workspace: {
                        ...savedWorkspace,
                        ...counters,
                        id: response.workspaceId,
                    },
                });
            }
            return response.workspaceId;
        },
        async addRepoToWorkspace({ commit }, args) {
            try {
                const { workspaceId, repoId, isPrivate } = args;
                const addRepoResult = await CloudFunctions.addRepoToWorkspace({ workspaceId, repoId, isPrivate });
                if (addRepoResult.data.code === StatusCodes.OK) {
                    commit('SET_REPOSITORY', { workspaceId, repoId });
                }
                return addRepoResult;
            } catch (error) {
                logger.error(`Error add adding a new repository to workspace: ${error}`, { module: 'database' });
                throw error;
            }
        },
        async updateRepoMetadata({ commit }, args) {
            const response = await firestore.getDocFromCollection(firestore.collectionNames.REPOSITORIES, args.repoId);
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching repo ${args.repoId}: ${response.errorMessage}`, { module: 'database' });
                return;
            }

            commit('SET_REPO_METADATA', { repoId: args.repoId, resource: { ...response.data, id: args.repoId } });
        },
        updateSwimmerStatusInStore({ commit, state }, args) {
            if (state.repositories[args.repoId]) {
                commit('SET_REPO_SWIMMER_STATUS', {
                    repoId: args.repoId,
                    userId: args.userId,
                    id: args.swimmId,
                    status: args.status,
                    swimmerName: args.swimmerName,
                });
            }
        },
        async archiveWorkspace({ commit, dispatch }, workspaceId) {
            const response = await firestore.updateDocInCollection(firestore.collectionNames.WORKSPACES, workspaceId, {
                deleted: true,
                invites: [],
            });
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error deleting workspace ${workspaceId}: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            // archive all workspace_users
            await dispatch('archiveFirebaseChildCollections', {
                collectionsList: [firestore.collectionNames.WORKSPACES_USERS],
                containerCollection: firestore.collectionNames.WORKSPACES,
                documentId: workspaceId,
            });
            commit('REMOVE_WORKSPACE', { workspaceId });
        },
        async archiveFirebaseChildCollections({ dispatch }, args) {
            const { collectionsList, containerCollection, documentId } = args;
            for (const collectionName of collectionsList) {
                const response = await firestore.getSubCollection(containerCollection, documentId, collectionName);
                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Got error while getting collection ${collectionName}: ${response.errorMessage}`, {
                        service: 'database',
                    });
                    continue;
                }
                const querySnapshot = response.data;
                await Promise.all(
                    querySnapshot.docs.map(async (doc) => {
                        await dispatch('archiveResource', {
                            resourceName: collectionName,
                            containerDocId: documentId,
                            containerCollectionType: containerCollection,
                            resourceId: doc.id,
                        });
                        const response = await firestore.deleteDocFromSubCollection(
                            containerCollection,
                            documentId,
                            collectionName,
                            doc.id
                        );
                        if (response.code !== config.SUCCESS_RETURN_CODE) {
                            logger.error(`Error deleting resource: ${response.errorMessage}`, { module: 'database' });
                            throw response.errorMessage;
                        }
                    })
                );
            }
        },
        async reloadWorkspaceUsers({ commit, state }, args) {
            const workspace = state.invitedWorkspaces[args.workspaceId];
            commit('SET_WORKSPACE', { workspaceId: workspace.id, workspace: { ...workspace, id: workspace.id } });
            commit('REMOVE_INVITED_WORKSPACE', { workspaceId: args.workspaceId });
        },
        async refreshWorkspaceLicense({ commit }, args) {
            const response = await firestore.getDocFromCollection(firestore.collectionNames.WORKSPACES, args.workspaceId);
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching workspace ${args.workspaceId}: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            const license = response.data.license;
            commit('REFRESH_WORKSPACE_LICENSE', { workspaceId: args.workspaceId, license });
        },
        async removeWorkspaceInvite({ commit }, args) {
            const { workspace, email } = args;
            if (workspace.invites) {
                const isInviteExist = workspace.invites.some((invite) => invite === email);
                if (isInviteExist) {
                    const invitesUpdate = {};
                    invitesUpdate['invites'] = await firestore.firestoreArrayRemove(email);
                    const response = await firestore.updateDocInCollection(
                        firestore.collectionNames.WORKSPACES,
                        workspace.id,
                        invitesUpdate
                    );
                    if (response.code !== config.SUCCESS_RETURN_CODE) {
                        logger.error(`Error removing workspace invite: ${response.errorMessage}`, { module: 'database' });
                        throw response.errorMessage;
                    }
                    commit('REMOVE_WORKSPACE_INVITE', { workspaceId: workspace.id, email });
                }
            }
        },
        async removeWorkspaceInviteRequest({ commit, state }, args) {
            const { workspaceId, email } = args;
            const workspace = state.workspaces[workspaceId];
            try {
                if (workspace['invite_requests']) {
                    const isInviteRequestExist = workspace['invite_requests'].find((request) => request === email);
                    if (isInviteRequestExist) {
                        await CloudFunctions.removeInviteRequest({ workspaceId, email });
                        commit('REMOVE_WORKSPACE_INVITE_REQUEST', { workspaceId, email });
                    }
                }
            } catch (error) {
                logger.error(`Error removing workspace invite request: ${error}`, { module: 'database' });
                throw error;
            }
        },
        addInviteEmailToWorkspace({ commit, state }, args) {
            try {
                const workspace = state.workspaces[args.workspaceId];
                const emailExists = workspace.invites.some((invite) => invite === args.email);
                if (!emailExists) {
                    commit('ADD_WORKSPACE_INVITE', { workspaceId: args.workspaceId, email: args.email });
                }
            } catch (error) {
                logger.error(`Error adding invite email to workspace: ${error} `, { module: 'database' });
            }
        },
        async fetchDomainSettings({ commit, rootState }) {
            const { user } = rootState.auth;
            const domain = user.email.split('@')[1];

            const response = await firestore.getDocFromCollection(firestore.collectionNames.DOMAINS, domain);
            if (response.code === config.SUCCESS_RETURN_CODE) {
                commit('SET_DOMAIN_SETTINGS', response.data);
            }
        },
        async saveUserAuthState(_, args) {
            const { userId, redirect } = args;
            const randomState = uuidv4();

            const authData = { state: randomState };
            if (redirect) {
                authData.redirect = redirect;
            }

            const response = await firestore.setValuesInDoc(firestore.collectionNames.USERS, userId, authData, {
                merge: true,
            });
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Failed generating github state to user: ${response.errorMessage}`, { module: 'database' });
                throw response.errorMessage;
            }

            return randomState;
        },
        removeUserFromWorkspaceState({ commit }, args) {
            commit('REMOVE_STORE_RESOURCE', {
                resourceName: 'workspace_users',
                containerDocId: args.workspaceId,
                resourceId: args.userId,
                storeType: 'workspaces',
            });
            if (args.isAdmin) {
                commit('REMOVE_STORE_RESOURCE', {
                    resourceName: 'workspace_admins',
                    containerDocId: args.workspaceId,
                    resourceId: args.userId,
                    storeType: 'workspaces',
                });
            }
        },
        async refreshAssignments({ commit, dispatch, getters }, { repoId, unitId }) {
            const assignments = await fetchDocAssignments({ docId: unitId, repoId });
            commit('SET_DOC_ASSIGNMENTS', {
                repoId: repoId,
                unitId: unitId,
                resource: assignments,
            });
        },
        async refreshContributors({ commit, dispatch, getters }, { repoId, unitId }) {
            try {
                const response = await firestore.getSubCollectionRecursive(
                    [
                        firestore.collectionNames.REPOSITORIES,
                        firestore.collectionNames.SWIMMS,
                        firestore.collectionNames.CONTRIBUTORS,
                    ],
                    [repoId, unitId]
                );
                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Error fetching doc contributors ${repoId}: ${unitId} ${response.errorMessage}`, {
                        module: 'database',
                    });
                    return;
                }
                response.data.forEach((contributor) => {
                    commit('SET_DOC_CONTRIBUTOR', {
                        repoId: repoId,
                        unitId: unitId,
                        resource: { id: contributor.id, ...contributor.data() },
                    });
                });
            } catch (err) {
                logger.error(`Error fetching doc contributors ${repoId}: ${unitId} ${err}`, { module: 'database' });
            }
        },
        async refreshThanks({ commit, dispatch, getters }, { repoId, unitId }) {
            try {
                const response = await firestore.getSubCollectionRecursive(
                    [firestore.collectionNames.REPOSITORIES, firestore.collectionNames.SWIMMS, firestore.collectionNames.THANKS],
                    [repoId, unitId]
                );
                if (response.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(`Error fetching doc thanks ${repoId}: ${unitId} ${response.errorMessage}`, {
                        module: 'database',
                    });
                    return;
                }
                response.data.forEach((thank) => {
                    commit('SET_DOC_THANK', {
                        repoId: repoId,
                        unitId: unitId,
                        resource: { id: thank.id, ...thank.data() },
                    });
                });
            } catch (err) {
                logger.error(`Error fetching doc thanks ${repoId}: ${unitId} ${err}`, { module: 'database' });
            }
        },
        async refreshWorkspaceUsersAndInvites({ commit, dispatch }, args) {
            await dispatch('fetchDocumentChildCollections', {
                documentId: args.workspaceId,
                children: [firestore.collectionNames.WORKSPACES_USERS, firestore.collectionNames.WORKSPACES_ADMINS],
                containerCollection: firestore.collectionNames.WORKSPACES,
            });
            const response = await firestore.getDocFromCollection(firestore.collectionNames.WORKSPACES, args.workspaceId);
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching workspace ${args.workspaceId}: ${response.errorMessage}`, { module: 'database' });
                return;
            }
            const invites = response.data.invites;
            commit('SET_WORKSPACE_RESOURCE', {
                resourceName: 'invites',
                workspaceId: args.workspaceId,
                resource: invites ? invites : [],
            });
        },
        async fetchUserNotifications({ commit, rootState }) {
            const { user } = rootState.auth;
            const byUidResponse = await firestore.getDocsRefWithWhereClause(firestore.collectionNames.NOTIFICATIONS, [
                'recipient_id',
                '==',
                user.uid,
            ]);

            if (byUidResponse.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error fetching notifications by uid for user ${user.uid}: ${byUidResponse.errorMessage}`, {
                    module: 'database',
                });
                return;
            }
            const uidNotifications = byUidResponse.data.docs.map((notification) => ({
                id: notification.id,
                ...notification.data(),
            }));

            if (user.email) {
                const byEmailResponse = await firestore.getDocsRefWithWhereClause(firestore.collectionNames.NOTIFICATIONS, [
                    'recipient_email',
                    '==',
                    user.email,
                ]);

                if (byEmailResponse.code !== config.SUCCESS_RETURN_CODE) {
                    logger.error(
                        `Error fetching notifications by email for email ${user.email}: ${byEmailResponse.errorMessage}`,
                        {
                            module: 'database',
                        }
                    );
                } else {
                    const emailNotifications = byEmailResponse.data.docs.map(
                        (notification) =>
                            !notification.recipient_id && {
                                id: notification.id,
                                ...notification.data(),
                            }
                    );
                    const combinedNotifications = uidNotifications.concat(emailNotifications);
                    const notifications = combinedNotifications.filter((notification) => notification);
                    commit('SET_USER_NOTIFICATIONS', { notifications });
                    return;
                }
            }

            const notifications = uidNotifications;
            commit('SET_USER_NOTIFICATIONS', { notifications });
        },
        async markNotificationAsSeen(_, notificationId) {
            const response = await firestore.updateDocInCollection(firestore.collectionNames.NOTIFICATIONS, notificationId, {
                seen: true,
                seen_at: await firestore.firestoreTimestamp(),
            });
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error marking notification ${notificationId} as seen: ${response.errorMessage}`, {
                    module: 'database',
                });
                return;
            }
        },
        async markNotificationAsDismissed(context, notificationId) {
            const response = await firestore.updateDocInCollection(firestore.collectionNames.NOTIFICATIONS, notificationId, {
                dismissed: true,
                dismissed_at: await firestore.firestoreTimestamp(),
            });
            if (response.code !== config.SUCCESS_RETURN_CODE) {
                logger.error(`Error marking notification ${notificationId} as dismissed: ${response.errorMessage}`, {
                    module: 'database',
                });
                return;
            }
        },
    },
    getters: {
        db_getUserWorkspaces: (state, getters) => (userId) => {
            return objectUtils.filter(state.workspaces, (workspace) => getters.db_isWorkspaceUser(workspace.id, userId));
        },
        db_getWorkspaceByRepo: (state, getters) => (repoId) => {
            for (const workspaceId of Object.keys(state.workspaces)) {
                if (getters.db_getWorkspaceRepoIds(workspaceId).includes(repoId)) {
                    return objectUtils.deepClone(state.workspaces[workspaceId]);
                }
            }
        },
        db_getWorkspaceRepoIds: (state) => (workspaceId) => {
            return state.workspaces[workspaceId] ? [...state.workspaces[workspaceId].repositories] : [];
        },
        db_getWorkspaceRepos: (state, getters) => (workspaceId) => {
            return getters.db_getWorkspaceRepoIds(workspaceId).map((repoId) => getters.db_getRepository(repoId));
        },
        db_getIsTeamViewVisible: (state, getters, rootState) => (repoId, workspaceId) => {
            const showTeamViewInWorkspace = !!state.workspaces[workspaceId] && !!state.workspaces[workspaceId].show_teamview;
            return (
                getters.db_isWorkspaceAdmin(workspaceId, rootState.auth.user.uid) &&
                (showTeamViewInWorkspace || getters.db_hasExercises(repoId))
            );
        },
        db_hasExercises: (_, getters) => (repoId) => {
            const swimms = getters.db_getSwimms(repoId) || {};
            // This might return extra exercises if there are "old" units without dod (considered as docs)
            return Object.values(swimms).some(
                (swimm) => swimm.type === 'unit' && swimm.play_mode !== UNIT_PLAY_MODES.WALKTHROUGH
            );
        },
        db_getResource: (state) => (resourcePath) => {
            // examples for resourcePath: workspaces.WORKSPACE_ID.plans.PLAN_ID, repositories.REPO_ID.playlists
            const splittedPath = resourcePath.split('.');
            let resource;
            if (splittedPath.length > 0) {
                resource = state;
                for (const pathPart of splittedPath) {
                    if (pathPart in resource) {
                        resource = resource[pathPart];
                    } else {
                        return undefined;
                    }
                }
            }
            return resource;
        },
        db_getClonedResource: (_, getters) => (resourcePath) => {
            const resource = getters.db_getResource(resourcePath);
            return resource ? objectUtils.deepClone(resource) : undefined;
        },
        db_hasWorkspaces: (_, getters) => (userId) => Object.keys(getters.db_getUserWorkspaces(userId)).length > 0,
        db_getWorkspace: (_, getters) => (workspaceId) => getters.db_getClonedResource(`workspaces.${workspaceId}`),
        db_getWorkspaceName: (_, getters) => (workspaceId) => {
            const workspace = getters.db_getResource(`workspaces.${workspaceId}`);
            return workspace ? workspace.name : undefined;
        },
        db_getWorkspaceUsers: (_, getters) => (workspaceId) =>
            getters.db_getClonedResource(`workspaces.${workspaceId}.workspace_users`),
        db_getWorkspaceAdmins: (_, getters) => (workspaceId) =>
            getters.db_getClonedResource(`workspaces.${workspaceId}.workspace_admins`),
        db_getWorkspaceResources: (_, getters) => (workspaceId) => {
            const workspaceRepos = getters.db_getWorkspaceRepos(workspaceId).filter((repo) => !!repo);
            const workspaceResources = [];
            for (const repo of Object.values(workspaceRepos)) {
                if (objectUtils.isEmpty(repo.metadata)) {
                    continue;
                }
                const repoId = repo.metadata.id;
                const swimms = [];
                for (const swimm of Object.values(getters.db_getSwimms(repoId))) {
                    const swimmResource = {
                        id: swimm.id,
                        name: swimm.name,
                        repoId: repoId,
                        type: swimm.type ? swimm.type : 'unit',
                        isExample: !!swimm.is_example,
                        creator_name: swimm.creator_name,
                        creator: swimm.creator,
                    };
                    if (swimm.play_mode) {
                        swimmResource.play_mode = swimm.play_mode;
                    }
                    if (swimm.counter_upvotes) {
                        swimmResource.counter_upvotes = swimm.counter_upvotes;
                    }
                    swimms.push(swimmResource);
                }
                const playlists = Object.values(getters.db_getPlaylists(repoId)).map((playlist) => ({
                    id: playlist.id,
                    name: playlist.name,
                    repoId: repo.metadata.id,
                    type: 'playlist',
                    isExample: !!playlist.is_example,
                }));
                workspaceResources.push(...swimms, ...playlists);
            }
            return workspaceResources;
        },
        db_isWorkspaceUser: (state) => (workspacesId, userId) =>
            !!state.workspaces[workspacesId] && userId in state.workspaces[workspacesId].workspace_users,
        db_getWorkspaceUser: (state, getters) => (workspaceId, userId) => {
            return getters.db_isWorkspaceUser(workspaceId, userId)
                ? state.workspaces[workspaceId].workspace_users[userId]
                : undefined;
        },
        db_isWorkspaceAdmin: (state) => (workspacesId, user) =>
            !!state.workspaces[workspacesId] && user in state.workspaces[workspacesId].workspace_admins,
        db_getAdminWorkspaces: (state, getters) => (user) =>
            objectUtils.filter(state.workspaces, (workspace) => getters.db_isWorkspaceAdmin(workspace.id, user)),
        db_getRepoMetadata: (_, getters) => (repoId) => getters.db_getClonedResource(`repositories.${repoId}.metadata`),
        db_getSwimms: (_, getters) => (repoId) => getters.db_getResource(`repositories.${repoId}.swimms`),
        db_getPlaylists: (_, getters) => (repoId) => getters.db_getResource(`repositories.${repoId}.playlists`),
        db_isUnitInRepo: (state) => (repoId, unitId) =>
            !!state.repositories[repoId] && unitId in state.repositories[repoId].swimms,
        db_isPlaylistInRepo: (state) => (repoId, playlistId) =>
            !!state.repositories[repoId] && playlistId in state.repositories[repoId].playlists,
        db_getUnits: (state) => (repoId) =>
            objectUtils.filter(state.repositories[repoId].swimms, (swimm) => swimm.type === 'unit'),
        db_getSwimm: (_, getters) => (repoId, swimmId) =>
            getters.db_getResource(`repositories.${repoId}.swimms.${swimmId}`),
        db_getAssignments: (_, getters) => (repoId, swimmId) =>
            Object.values(getters.db_getResource(`repositories.${repoId}.swimms.${swimmId}.assignments`) || {}),
        db_getContributors: (_, getters) => (repoId, swimmId) =>
            Object.values(getters.db_getResource(`repositories.${repoId}.swimms.${swimmId}.contributors`) || {}),
        db_getThanks: (_, getters) => (repoId, swimmId) =>
            Object.values(getters.db_getResource(`repositories.${repoId}.swimms.${swimmId}.thanks`) || {}),
        db_getResourceViews: (state, getters) => (repoId, resourceId, type) => {
            const resource = getters.db_getResource(`repositories.${repoId}.${type}.${resourceId}`);
            return resource && resource.views ? resource.views : null;
        },
        db_getPlaylist: (_, getters) => (repoId, playlistId) =>
            getters.db_getResource(`repositories.${repoId}.playlists.${playlistId}`),
        db_getRepository: (_, getters) => (repoId) => getters.db_getResource(`repositories.${repoId}`),
        db_getSwimmStatus: (state) => (repoId, swimmerId, swimmId) => {
            if (!(repoId in state.repositories)) {
                return null;
            }
            const swimmer = state.repositories[repoId].swimmers[swimmerId];
            if (
                !!swimmer &&
                Object.keys(swimmer).includes('swimms_status') &&
                Object.keys(swimmer.swimms_status).includes(swimmId)
            ) {
                return swimmer.swimms_status[swimmId].status;
            }
            return 'not started';
        },
        db_getSwimmerRepos: (state, getters) => (swimmerId) => {
            return objectUtils.filter(state.repositories, (repo) => getters.db_isRepoSwimmer(repo.metadata.id, swimmerId));
        },
        db_isRepoSwimmer: (state) => (repoId, user) =>
            state.repositories[repoId] && user in state.repositories[repoId].swimmers,
        db_isRepoLifeguard: (state) => (repoId, user) =>
            state.repositories[repoId] && user in state.repositories[repoId].lifeguards,
        db_isPublicRepo: (state) => (repoId) => state.repositories[repoId].metadata.is_public === true, // For opensource
        db_isPrivateRepo: (state) => (repoId) => state.repositories[repoId].metadata.is_private !== false,
        db_isRepoSubscribed: (state) => (repoId) => !!state.repositories[repoId] && state.repositories[repoId].subscribed,
        db_getUnitsOrderedByStatus: (state, getters) => (repoId, swimmerId) => {
            if (!(repoId in state['repositories']) || !('swimms' in state['repositories'][repoId])) {
                return [];
            }
            const statusOrder = { 'not started': 1, started: 2, done: 3 };
            const status = (swimm) => getters.db_getSwimmStatus(repoId, swimmerId, swimm.id);
            const sortByStatus = (first, second) => statusOrder[status(first)] - statusOrder[status(second)];
            return Object.values(getters.db_getUnits(repoId)).sort(sortByStatus);
        },

        db_getOpenSourceRepoIds: (state) => () =>
            Object.keys(objectUtils.filter(state.repositories, (repo) => repo.metadata.is_open_source)),
        db_isUpvoted: (state) => (containerType, containerId, resourceType, resourceId) =>
            state.upvotes[containerType][containerId] &&
            state.upvotes[containerType][containerId][resourceType][resourceId] &&
            state.upvotes[containerType][containerId][resourceType][resourceId].upvote,
        db_isOriginallyUpvoted: (state) => (containerType, containerId, resourceType, resourceId) =>
            state.upvotes[containerType][containerId] &&
            state.upvotes[containerType][containerId][resourceType][resourceId] &&
            state.upvotes[containerType][containerId][resourceType][resourceId].originalValue,
        db_getNotifications: (state) => () => state.notifications || [],
    },
};
